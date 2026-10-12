'use strict';
const assert=require('node:assert/strict'),ts=require('typescript');
const S=require('./schema.cjs');
function parse(file,text){const source=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true);assert.equal(source.parseDiagnostics.length,0,'invalid TypeScript source');return source;}
function route(node){
 if(ts.isStringLiteral(node)||ts.isNoSubstitutionTemplateLiteral(node))return node.text;
 if(ts.isTemplateExpression(node))return node.head.text+node.templateSpans.map(span=>'{parameter}'+span.literal.text).join('');
 assert.fail('unsupported dynamic client route');
}
function inventory(files){
 const result=[];
 for(const [file,text]of Object.entries(files)){
  const source=parse(file,text),receivers=new Set();let resource=false,http=false;
  for(const node of source.statements)if(ts.isImportDeclaration(node)){
   const imported=node.moduleSpecifier.text;
   assert(!/^(axios|node:https?|https?)$/.test(imported),'unsupported HTTP client import');
   if(imported==='@angular/common/http'){
    const bindings=node.importClause?.namedBindings;assert(bindings&&ts.isNamedImports(bindings),'unsupported HTTP namespace import');
    for(const item of bindings.elements){assert(!item.propertyName&&['httpResource','HttpClient','provideHttpClient','HttpHeaders','HttpErrorResponse','HttpInterceptorFn','withInterceptors'].includes(item.name.text),'unsupported HTTP client import');resource||=item.name.text==='httpResource';http||=item.name.text==='HttpClient';}
   }
  }
  function binding(node){
   if(http&&(ts.isVariableDeclaration(node)||ts.isPropertyDeclaration(node)||ts.isParameter(node))&&node.name&&ts.isIdentifier(node.name)){
    const inject=node.initializer;
    const typed=node.type&&ts.isTypeReferenceNode(node.type)&&node.type.typeName.getText(source)==='HttpClient';
    const injected=inject&&ts.isCallExpression(inject)&&inject.expression.getText(source)==='inject'&&inject.arguments.length===1&&inject.arguments[0].getText(source)==='HttpClient';
    if(typed||injected)receivers.add((ts.isPropertyDeclaration(node)||ts.isParameter(node)&&node.modifiers?'this.':'')+node.name.text);
   }
   ts.forEachChild(node,binding);
  }
  binding(source);
  function visit(node){
   if(ts.isIdentifier(node)&&node.text==='httpResource'){
    const parent=node.parent;
    const imported=ts.isImportSpecifier(parent)&&parent.name===node&&!parent.propertyName&&parent.parent.parent.parent.moduleSpecifier.text==='@angular/common/http';
    const called=ts.isCallExpression(parent)&&parent.expression===node;
    assert(imported||(resource&&called),'unsupported httpResource alias or indirect use');
   }
   if(ts.isIdentifier(node)&&node.text==='fetch')assert.fail('unsupported fetch client');
   if(ts.isPropertyAccessExpression(node)&&['globalThis','window'].includes(node.expression.getText(source))&&node.name.text==='fetch')assert.fail('unsupported fetch client');
   if((ts.isIdentifier(node)||ts.isPropertyAccessExpression(node))&&receivers.has(node.getText(source))){
    const parent=node.parent;
    const declared=(ts.isVariableDeclaration(parent)||ts.isPropertyDeclaration(parent)||ts.isParameter(parent))&&parent.name===node;
    const called=ts.isPropertyAccessExpression(parent)&&parent.expression===node&&ts.isCallExpression(parent.parent)&&parent.parent.expression===parent;
    assert(declared||called,'unsupported HttpClient alias or indirect use');
   }
   if(ts.isCallExpression(node)){
    const e=node.expression;let method,url;
    if(ts.isIdentifier(e)&&e.text==='fetch')assert.fail('unsupported fetch client');
    if(ts.isIdentifier(e)&&e.text==='httpResource'){
     assert(resource,'missing canonical httpResource import');assert(node.arguments.length===1&&ts.isArrowFunction(node.arguments[0])&&node.arguments[0].parameters.length===0,'unsupported HTTP resource arguments');
     method='GET';url=route(node.arguments[0].body);
    }else if(ts.isPropertyAccessExpression(e)&&e.expression.getText(source)==='httpResource')assert.fail('unsupported HTTP resource variant');
    else if(ts.isPropertyAccessExpression(e)&&receivers.has(e.expression.getText(source))){
     assert(['get','post','put','patch','delete'].includes(e.name.text),'unsupported HttpClient operation');assert(node.arguments.length>=1);method=e.name.text.toUpperCase();url=route(node.arguments[0]);
     if(['POST','PUT','PATCH'].includes(method))assert(node.arguments.length>=2,'missing request body');
    }
    if(method){assert(node.typeArguments?.length===1&&ts.isTypeReferenceNode(node.typeArguments[0])&&ts.isIdentifier(node.typeArguments[0].typeName),'explicit generated response type required');assert(url.startsWith('/')&&!url.startsWith('//')&&!url.includes('?')&&!url.includes('#'),'unsupported client URL');result.push({file,method,path:url,typeName:node.typeArguments[0].typeName.text});}
   }
   ts.forEachChild(node,visit);
  }
  visit(source);
 }
 return result;
}
function operationFor(call,ops){
 const pattern=path=>path.replace(/\{[^}]+\}/g,'{}');
 const matches=Object.values(ops).filter(op=>op.method===call.method&&pattern(op.path)===pattern(call.path));assert(matches.length<=1,'ambiguous client operation');return matches[0];
}
function equivalent(actual,expected,names){
 // TypeScript's checker compares the generated and declared structural types.
 // No client code is executed or emitted; only standard library declarations are read.
 const filename='/__harness_contract_types.ts';
 assert(!/@ts-(?:ignore|nocheck|expect-error)/.test(actual),'TypeScript suppression in generated types');
 const parsed=parse('actual.ts',actual),statements=parsed.statements;
 assert(!parsed.referencedFiles.length&&!parsed.typeReferenceDirectives.length&&!parsed.libReferenceDirectives.length,'external generated type reference');
 assert(statements.every(n=>ts.isInterfaceDeclaration(n)||ts.isTypeAliasDeclaration(n)),'generated file must contain type declarations only');
 const expectedDeclarations=parse('expected.ts',expected).statements;
 // Caller response names cannot narrow the generated contract integrity check.
 names=expectedDeclarations.map(node=>node.name.text);
 for(const name of names)assert(/^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
 if(S.canonical(statements.map(n=>n.name.text).sort())!==S.canonical(expectedDeclarations.map(n=>n.name.text).sort()))return false;
 function safe(node){assert(node.kind!==ts.SyntaxKind.AnyKeyword,'any is not a generated contract type');ts.forEachChild(node,safe);}
 for(const declaration of statements)safe(declaration);
 const text=actual+'\nnamespace __Expected {\n'+expected+'\n}\n'+names.map((name,index)=>`let a${index}!: ${name};let b${index}!: __Expected.${name};a${index}=b${index};b${index}=a${index};`).join('\n');
 const options={strict:true,noEmit:true,target:ts.ScriptTarget.ES2022,skipLibCheck:false};
 const host=ts.createCompilerHost(options),read=host.readFile.bind(host),exists=host.fileExists.bind(host);
 host.readFile=file=>file===filename?text:read(file);host.fileExists=file=>file===filename||exists(file);
 host.getSourceFile=(file,language)=>{const body=host.readFile(file);return body===undefined?undefined:ts.createSourceFile(file,body,language,true);};
 const program=ts.createProgram([filename],options,host);
 return ts.getPreEmitDiagnostics(program).length===0;
}
function checkTypes(actual,expected,names){assert(equivalent(actual,expected,names),'generated type was edited without regeneration');}
module.exports={parse,inventory,operationFor,equivalent,checkTypes};
