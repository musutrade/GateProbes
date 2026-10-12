'use strict';
const assert=require('node:assert/strict');
const canonical=value=>JSON.stringify(sort(value));
function sort(value){if(Array.isArray(value))return value.map(sort);if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(k=>[k,sort(value[k])]));return value;}
function keys(value,allowed){assert(value&&typeof value==='object'&&!Array.isArray(value));for(const key of Object.keys(value))assert(allowed.includes(key),'unsupported field: '+key);}
function schema(value,spec,seen=[]){
 keys(value,['$ref','type','properties','required','additionalProperties','items','enum','nullable','description','minimum','maximum','minLength','maxLength','minItems','maxItems','pattern']);
 if(value.$ref){assert.deepEqual(Object.keys(value),['$ref']);assert(/^#\/components\/schemas\/[A-Za-z_][A-Za-z0-9_]*$/.test(value.$ref),'external/unsupported reference');assert(!seen.includes(value.$ref),'recursive schema');const name=value.$ref.split('/').pop();assert(spec.components?.schemas?.[name],'unresolved schema');return schema(spec.components.schemas[name],spec,[...seen,value.$ref]);}
 assert(['object','array','string','integer','number','boolean'].includes(value.type),'unsupported JSON type');
 const result={...value};delete result.description;
 for(const [kind,fields]of [['string',['minLength','maxLength','pattern']],['array',['minItems','maxItems']]])for(const field of fields)if(value[field]!==undefined)assert.equal(value.type,kind,'constraint/type mismatch');
 for(const field of ['minimum','maximum'])if(value[field]!==undefined)assert(['number','integer'].includes(value.type),'constraint/type mismatch');
 if(value.nullable!==undefined)assert(typeof value.nullable==='boolean');
 if(value.enum){assert(Array.isArray(value.enum)&&value.enum.length);assert.equal(new Set(value.enum.map(canonical)).size,value.enum.length);for(const item of value.enum)validate({...result,enum:undefined},item);result.enum=[...value.enum].sort((a,b)=>canonical(a).localeCompare(canonical(b)));}
 for(const key of ['minimum','maximum','minLength','maxLength','minItems','maxItems'])if(value[key]!==undefined)assert(Number.isFinite(value[key])&&(['minimum','maximum'].includes(key)||Number.isSafeInteger(value[key])&&value[key]>=0));
 if(value.pattern!==undefined){assert.equal(value.type,'string');new RegExp(value.pattern);}
 if(value.type==='object'){
  assert(value.additionalProperties===false,'object must be closed');assert(value.properties&&typeof value.properties==='object');
  result.required=[...(value.required||[])].sort();assert.equal(new Set(result.required).size,result.required.length);
  assert(result.required.every(name=>Object.hasOwn(value.properties,name)),'unknown required property');
  result.properties=Object.fromEntries(Object.entries(value.properties).sort(([a],[b])=>a.localeCompare(b)).map(([name,child])=>{assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(name));return[name,schema(child,spec,seen)];}));
 }else {for(const key of ['properties','required','additionalProperties'])assert(value[key]===undefined,'object-only schema field');}
 if(value.type==='array')result.items=schema(value.items,spec,seen);else assert(value.items===undefined);
 return result;
}
function validate(s,value){
 if(value===null){assert(s.nullable,'unexpected null');return;}
 if(s.enum)assert(s.enum.some(item=>canonical(item)===canonical(value)),'provider enum drift');
 if(s.type==='object'){
  assert(value&&typeof value==='object'&&!Array.isArray(value),'expected object');
  assert(Object.keys(value).every(name=>Object.hasOwn(s.properties,name)),'provider field drift');
  assert((s.required||[]).every(name=>Object.hasOwn(value,name)),'missing required field');
  for(const [name,item]of Object.entries(value))validate(s.properties[name],item);
 }else if(s.type==='array'){
  assert(Array.isArray(value),'expected array');for(const item of value)validate(s.items,item);
  if(s.minItems!==undefined)assert(value.length>=s.minItems);if(s.maxItems!==undefined)assert(value.length<=s.maxItems);
 }else if(s.type==='string'){
  assert.equal(typeof value,'string');if(s.minLength!==undefined)assert([...value].length>=s.minLength);if(s.maxLength!==undefined)assert([...value].length<=s.maxLength);if(s.pattern!==undefined)assert(new RegExp(s.pattern).test(value));
 }else if(s.type==='boolean')assert.equal(typeof value,'boolean');
 else{assert(typeof value==='number'&&Number.isFinite(value));if(s.type==='integer')assert(Number.isSafeInteger(value),'expected safe integer');if(s.minimum!==undefined)assert(value>=s.minimum);if(s.maximum!==undefined)assert(value<=s.maximum);}
}
function operations(spec){
 keys(spec,['info','openapi','paths','components']);assert.equal(spec.openapi,'3.0.3');
 if(spec.components){keys(spec.components,['schemas']);for(const item of Object.values(spec.components.schemas||{}))schema(item,spec);}
 const result={},ids=new Set();
 for(const [path,methods]of Object.entries(spec.paths)){
  assert(/^\/(?:[A-Za-z0-9_-]+|\{[A-Za-z_][A-Za-z0-9_]*\})(?:\/(?:[A-Za-z0-9_-]+|\{[A-Za-z_][A-Za-z0-9_]*\}))*$/.test(path),'unsupported path');
  keys(methods,['get','post','put','patch','delete']);
  for(const [method,op]of Object.entries(methods)){
   keys(op,['operationId','responses','parameters','requestBody','summary','description']);assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(op.operationId));assert(!ids.has(op.operationId),'duplicate operationId');ids.add(op.operationId);
   const parameters=(op.parameters||[]).map(p=>{keys(p,['name','in','required','schema','description']);assert(['path','query','header'].includes(p.in));assert(typeof p.name==='string'&&p.name);if(p.in==='path')assert(p.required===true);return {name:p.name,in:p.in,required:p.required===true,schema:schema(p.schema,spec)};});
   assert.equal(new Set(parameters.map(p=>p.in+':'+p.name)).size,parameters.length,'duplicate parameter');
   assert.deepEqual(parameters.filter(p=>p.in==='path').map(p=>p.name).sort(),[...path.matchAll(/\{(\w+)\}/g)].map(m=>m[1]).sort(),'path parameters must be declared');
   let request=null;if(op.requestBody){keys(op.requestBody,['required','content','description']);assert(typeof op.requestBody.required==='boolean');request={required:op.requestBody.required,schema:content(op.requestBody.content,spec)};}
   const responses={};for(const [status,response]of Object.entries(op.responses)){
    assert(/^[1-5][0-9]{2}$/.test(status));keys(response,['description','content']);assert(typeof response.description==='string');responses[status]=response.content===undefined?{type:'void'}:content(response.content,spec);
   }
   assert(Object.keys(responses).length);const upper=method.toUpperCase();result[upper+' '+path]={operationId:op.operationId,method:upper,path,parameters,request,responses};
  }
 }
 assert(Object.keys(result).length,'empty contract');return result;
}
function content(value,spec){assert.deepEqual(Object.keys(value||{}),['application/json']);keys(value['application/json'],['schema']);return schema(value['application/json'].schema,spec);}
function type(s){if(s.type==='void')return 'undefined';let result;if(s.enum)result=s.enum.map(JSON.stringify).join(' | ');else if(s.type==='object')result='{ '+Object.entries(s.properties).map(([name,child])=>name+(s.required.includes(name)?'':'?')+': '+type(child)+';').join(' ')+' }';else if(s.type==='array')result='Array<'+type(s.items)+'>';else result=s.type==='integer'?'number':s.type;if(s.nullable)result+=' | null';return result;}
function name(op){return op.operationId==='getHealth'?'HealthResponse':op.operationId[0].toUpperCase()+op.operationId.slice(1)+'Response';}
function generate(spec,typeName,digest){
 assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(typeName));const ops=Object.values(operations(spec));
 let output='// harness-contract-sha256: '+digest+'\n';
 for(const op of ops){const n=ops.length===1?typeName:name(op);const variants=Object.values(op.responses);
  const closedEnums=variants.every(s=>s.type==='object'&&!s.nullable&&Object.keys(s.properties).length===s.required.length&&Object.values(s.properties).every(p=>p.type==='string'&&p.enum&&!p.nullable));
  if(closedEnums&&variants.every(s=>canonical(Object.keys(s.properties))===canonical(Object.keys(variants[0].properties)))){
   const props=Object.keys(variants[0].properties).sort().map(k=>'  '+k+': '+[...new Set(variants.flatMap(s=>s.properties[k].enum))].sort().map(JSON.stringify).join(' | ')+';').join('\n');output+='export interface '+n+' {\n'+props+'\n}\n';
  }else output+='export type '+n+' = '+[...new Set(variants.map(type))].join(' | ')+';\n';
  if(op.request)output+='export type '+n.replace(/Response$/,'Request')+' = '+type(op.request.schema)+';\n';
 }
 return output;
}
module.exports={canonical,keys,schema,validate,operations,type,name,generate};
