'use strict';
const assert = require('node:assert/strict');
const ts = require('typescript');
const canonical = value => JSON.stringify(sort(value));
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,sort(value[k])]));
  return value;
}
function fields(schema) {
  assert.deepEqual(Object.keys(schema).sort(), ['additionalProperties','properties','required','type']);
  assert.equal(schema.type,'object'); assert.equal(schema.additionalProperties,false);
  assert.deepEqual([...schema.required].sort(),Object.keys(schema.properties).sort());
  const result={};
  for (const [name,property] of Object.entries(schema.properties)) {
    assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(name),'unsupported property identifier');
    assert.deepEqual(Object.keys(property).sort(),['enum','type']); assert.equal(property.type,'string');
    assert(property.enum.length && property.enum.every(s=>typeof s==='string'));
    assert.equal(new Set(property.enum).size,property.enum.length);
    result[name]=[...property.enum].sort();
  }
  return result;
}
function operations(spec) {
  assert.deepEqual(Object.keys(spec).sort(),['info','openapi','paths']); assert.equal(spec.openapi,'3.0.3');
  const result={};
  for (const [path,methods] of Object.entries(spec.paths)) {
    assert(/^\/[a-zA-Z0-9/_-]+$/.test(path),'unsupported parameterized path');
    assert.deepEqual(Object.keys(methods),['get'],'only parameter-free GET is supported');
    const get=methods.get;
    assert.deepEqual(Object.keys(get).sort(),['operationId','responses']);
    assert(typeof get.operationId==='string' && get.operationId);
    const responses={};
    for (const [status,response] of Object.entries(get.responses)) {
      assert(/^[1-5][0-9]{2}$/.test(status));
      assert.deepEqual(Object.keys(response).sort(),['content','description']);
      assert.deepEqual(Object.keys(response.content),['application/json']);
      assert.deepEqual(Object.keys(response.content['application/json']),['schema']);
      responses[status]=fields(response.content['application/json'].schema);
    }
    assert(Object.keys(responses).length,'missing response variants');
    result[path]={operationId:get.operationId,responses};
  }
  assert(Object.keys(result).length,'empty contract'); return result;
}
function parse(file,text) {
  const source=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true);
  assert.equal(source.parseDiagnostics.length,0,'invalid TypeScript source'); return source;
}
function consumer(typeText,clientText,typeName) {
  const source=parse('response.ts',typeText);
  const declarations=source.statements.filter(n=>ts.isInterfaceDeclaration(n)&&n.name.text===typeName);
  assert.equal(declarations.length,1,'missing/ambiguous consumer response type');
  const declaration=declarations[0]; assert(!declaration.heritageClauses && !declaration.typeParameters);
  const shape={};
  for (const n of declaration.members) {
    assert(ts.isPropertySignature(n)&&ts.isIdentifier(n.name)&&!n.questionToken&&n.type,'unsupported consumer member');
    assert(!(n.name.text in shape),'duplicate consumer field');
    const types=ts.isUnionTypeNode(n.type)?n.type.types:[n.type];
    shape[n.name.text]=types.map(t=>{assert(ts.isLiteralTypeNode(t)&&ts.isStringLiteral(t.literal),'unsupported consumer type');return t.literal.text;}).sort();
  }
  const client=parse('client.ts',clientText), calls=[];
  // Resolve only the canonical imported binding. Aliases/other client APIs must
  // receive a certified adapter instead of silently disappearing from inventory.
  let imported=false;
  for(const n of client.statements) if(ts.isImportDeclaration(n)&&n.moduleSpecifier.text==='@angular/common/http') {
    const bindings=n.importClause?.namedBindings;
    assert(bindings&&ts.isNamedImports(bindings));
    imported ||= bindings.elements.some(e=>e.name.text==='httpResource'&&!e.propertyName);
  }
  assert(imported,'missing canonical httpResource import');
  function visit(n) {
    if(ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&n.expression.text==='httpResource') {
      assert(n.typeArguments?.length===1&&ts.isTypeReferenceNode(n.typeArguments[0])&&n.typeArguments[0].typeName.getText(client)===typeName);
      assert(n.arguments.length===1&&ts.isArrowFunction(n.arguments[0])&&n.arguments[0].parameters.length===0&&ts.isStringLiteral(n.arguments[0].body),'unsupported dynamic client route');
      calls.push(n.arguments[0].body.text);
    }
    ts.forEachChild(n,visit);
  }
  visit(client); assert.equal(calls.length,1,'consumer must declare one supported call');
  return {path:calls[0],fields:shape};
}
function measure(base,head,typeText,clientText,typeName,observations) {
  const previous=operations(base), current=operations(head);
  const breaking=Object.entries(previous).filter(([p,operation])=>canonical(operation)!==canonical(current[p])).length;
  const client=consumer(typeText,clientText,typeName), operation=current[client.path];
  let drift=!operation;
  if(operation) {
    const union={};
    for(const shape of Object.values(operation.responses)) for(const [field,values] of Object.entries(shape)) union[field]=[...new Set([...(union[field]||[]),...values])].sort();
    drift=canonical(union)!==canonical(client.fields);
  }
  const seen=new Set();
  for(const observation of observations) {
    assert.deepEqual(Object.keys(observation).sort(),['body','content_type','method','path','status']);
    assert.equal(observation.method,'GET'); assert(observation.content_type.toLowerCase().startsWith('application/json'));
    const key=observation.path+':'+observation.status;
    assert(!seen.has(key),'duplicate response observation');seen.add(key);
    const expected=current[observation.path]?.responses[String(observation.status)];assert(expected,'undeclared response');
    assert.deepEqual(Object.keys(observation.body).sort(),Object.keys(expected).sort(),'provider field drift');
    for(const [field,values] of Object.entries(expected)) assert(values.includes(observation.body[field]),'provider value drift');
  }
  const required=Object.entries(current).flatMap(([p,o])=>Object.keys(o.responses).map(s=>p+':'+s));
  assert.deepEqual([...seen].sort(),required.sort(),'missing provider response variant');
  return {'contract.breaking_changes':{type:'count',value:breaking},'contract.client_drift':{type:'boolean',value:drift},'contract.compatible':{type:'boolean',value:!breaking&&!drift}};
}
function consumerInventory(files, expectedClient) {
 const calls=[];
 for(const [name,text] of Object.entries(files)) {
  const source=parse(name,text);
  for(const node of source.statements) if(ts.isImportDeclaration(node)&&node.moduleSpecifier.text==='@angular/common/http') {
   const bindings=node.importClause?.namedBindings;assert(bindings&&ts.isNamedImports(bindings),'unsupported HTTP namespace import');
   for(const item of bindings.elements) assert(!item.propertyName&&['httpResource','provideHttpClient'].includes(item.name.text),'unsupported HTTP client import');
  }
  function visit(node) {
   if(ts.isCallExpression(node)) {
    const expression=node.expression;
    if(ts.isIdentifier(expression)&&expression.text==='httpResource') calls.push(name);
    if(ts.isPropertyAccessExpression(expression)&&expression.expression.getText(source)==='httpResource') assert.fail('unsupported HTTP resource variant');
   }
   ts.forEachChild(node,visit);
  }
  visit(source);
 }
 assert.deepEqual(calls,[expectedClient],'unexpected or missing production HTTP consumer');
}
function generate(spec,typeName,digest) {
 assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(typeName));
 const entries=Object.values(operations(spec));assert.equal(entries.length,1,'generator expects one operation');
 const union={};for(const fields of Object.values(entries[0].responses)) for(const [key,values] of Object.entries(fields)) union[key]=[...new Set([...(union[key]||[]),...values])].sort();
 const properties=Object.entries(union).sort().map(([name,values])=>`  ${name}: ${values.map(v=>JSON.stringify(v)).join(' | ')};`).join('\n');
 return `// harness-contract-sha256: ${digest}\nexport interface ${typeName} {\n${properties}\n}\n`;
}
module.exports={canonical,operations,consumer,consumerInventory,measure,generate};
