'use strict';
const assert=require('node:assert/strict'),S=require('./schema.cjs'),C=require('./clients.cjs');
const {consumer}=require('./legacy-measure.cjs');
function consumerInventory(files,expectedClient,spec){
 const calls=C.inventory(files);assert(calls.some(call=>call.file===expectedClient),'missing expected production HTTP consumer');
 if(spec){const ops=S.operations(spec);for(const call of calls)assert(C.operationFor(call,ops),'undeclared production HTTP consumer');}
 else assert(calls.length===1,'extra consumers require a complete operation contract');
 return calls;
}
function measure(base,head,typeText,clientText,typeName,observations,files){
 const previous=S.operations(base),current=S.operations(head);
 const breaking=Object.entries(previous).filter(([key,op])=>S.canonical(op)!==S.canonical(current[key])).length;
 const calls=C.inventory(files||{'client.ts':clientText});assert(calls.length,'missing production HTTP consumer');
 const expected=S.generate(head,typeName,'check');
 let drift=false;const typeNames=[];
 for(const call of calls){const op=C.operationFor(call,current);if(!op){drift=true;continue;}const expectedName=Object.keys(current).length===1?typeName:S.name(op);if(call.typeName!==expectedName)drift=true;else typeNames.push(call.typeName);}
 if(!C.equivalent(typeText,expected,[...new Set(typeNames)]))drift=true;
 const seen=new Set();
 for(const o of observations){
  S.keys(o,['body','content_type','method','path','status','operation_path','request_body']);
  assert(typeof o.method==='string'&&typeof o.path==='string');assert(typeof o.content_type==='string');
  const key=o.method+' '+(o.operation_path||o.path),op=current[key];assert(op,'undeclared response');
  if(o.operation_path){const escape=s=>s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');const pattern=op.path.split(/(\{\w+\})/).map(s=>s.startsWith('{')?'[^/?#]+':escape(s)).join('');assert(new RegExp('^'+pattern+'$').test(o.path),'observation route mismatch');}
  const variant=key+':'+o.status;assert(!seen.has(variant),'duplicate response observation');seen.add(variant);
  const expectedBody=op.responses[String(o.status)];assert(expectedBody,'undeclared response');if(expectedBody.type==='void'){assert.equal(o.body,null,'unexpected body');assert.equal(o.content_type,'','unexpected content type');}else{assert(o.content_type.toLowerCase().startsWith('application/json'));S.validate(expectedBody,o.body);}
  if(op.request&&o.status>=200&&o.status<300){assert(o.request_body!==undefined||!op.request.required,'missing observed request');if(o.request_body!==undefined)S.validate(op.request.schema,o.request_body);}
 }
 const required=Object.entries(current).flatMap(([key,op])=>Object.keys(op.responses).map(status=>key+':'+status));assert.deepEqual([...seen].sort(),required.sort(),'missing provider response variant');
 return {'contract.breaking_changes':{type:'count',value:breaking},'contract.client_drift':{type:'boolean',value:drift},'contract.compatible':{type:'boolean',value:!breaking&&!drift}};
}
module.exports={canonical:S.canonical,operations:S.operations,generate:S.generate,consumer,consumerInventory,measure};
