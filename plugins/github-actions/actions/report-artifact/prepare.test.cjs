'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {sha,validate,prepare}=require('./prepare.cjs');
function fixture(t){
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'html-artifact-test-')));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const input=path.join(root,'input');fs.mkdirSync(input);const html=Buffer.from('<!doctype html><title>Synthetic FAIL</title>');
 const p={commit:'a'.repeat(40),core_status:'FAIL',evidence_complete:true,html:{path:'test_result.html',sha256:sha(html),size_bytes:html.length},index_sha256:'b'.repeat(64),invocation_id:'inv-1',machine_sha256:'c'.repeat(64),manifest_sha256:'d'.repeat(64),schema:'harness-html-export/v1'};
 const options={directory:input,digest:'',commit:p.commit,upload:'false',retention:'7',temp:root,runId:'123',attempt:'1'};
 function write(){const bytes=Buffer.from(JSON.stringify(p,null,2));fs.writeFileSync(path.join(input,'provenance.json'),bytes);options.digest=sha(bytes);}
 fs.writeFileSync(path.join(input,'test_result.html'),html);fs.writeFileSync(path.join(input,'raw-evidence.log'),'do not upload');write();return {root,input,html,p,options,write};
}
test('default validation is local and FAIL remains FAIL; opt-in stages only verified display bytes',t=>{
 const f=fixture(t);assert.deepEqual(prepare(f.options),{validated:true,status:'FAIL'});assert.deepEqual(fs.readdirSync(f.root),['input']);
 const result=prepare({...f.options,upload:'true'});assert.equal(result.status,'FAIL');assert.equal(result.name,`gatehouse-html-${f.p.commit}-123-1`);assert.deepEqual(fs.readdirSync(result.directory).sort(),['provenance.json','test_result.html']);assert.deepEqual(fs.readFileSync(path.join(result.directory,'test_result.html')),f.html);
 f.p.core_status='PASS';f.write();assert.equal(validate(f.options).status,'PASS');
});
test('pins, commit and file contents fail closed',t=>{
 const f=fixture(t);assert.throws(()=>prepare({...f.options,digest:'e'.repeat(64)}));assert.throws(()=>prepare({...f.options,commit:'f'.repeat(40)}));
 fs.writeFileSync(path.join(f.input,'test_result.html'),'changed');assert.throws(()=>prepare(f.options));fs.writeFileSync(path.join(f.input,'test_result.html'),f.html);
 fs.appendFileSync(path.join(f.input,'provenance.json'),' ');assert.throws(()=>prepare(f.options));
});
test('completeness, status, exact schema, identities and HTML path are required',t=>{
 const f=fixture(t);for(const [key,value] of [['evidence_complete',false],['core_status','pass'],['schema','future'],['invocation_id','bad\nvalue'],['machine_sha256','no'],['unexpected','field']]){
  const old=f.p[key];f.p[key]=value;f.write();assert.throws(()=>prepare(f.options));if(old===undefined)delete f.p[key];else f.p[key]=old;
 }
 f.p.html.path='../raw-evidence.log';f.write();assert.throws(()=>prepare(f.options));
});
test('duplicate JSON fields, excessive files and symlinks are rejected',t=>{
 const f=fixture(t);let bytes=Buffer.from(JSON.stringify(f.p,null,2).replace('{','{\n  "core_status": "PASS",'));fs.writeFileSync(path.join(f.input,'provenance.json'),bytes);f.options.digest=sha(bytes);assert.throws(()=>prepare(f.options));f.write();
 fs.writeFileSync(path.join(f.input,'test_result.html'),Buffer.alloc(2*1024*1024+1));assert.throws(()=>prepare(f.options));fs.unlinkSync(path.join(f.input,'test_result.html'));
 fs.writeFileSync(path.join(f.root,'outside.html'),f.html);fs.symlinkSync(path.join(f.root,'outside.html'),path.join(f.input,'test_result.html'));assert.throws(()=>prepare(f.options));
 fs.writeFileSync(path.join(f.input,'provenance.json'),Buffer.alloc(65537));assert.throws(()=>prepare(f.options));
});
test('invalid authorization, retention and Actions identities cannot stage uploads',t=>{
 const f=fixture(t);for(const upload of ['yes','','TRUE'])assert.throws(()=>prepare({...f.options,upload}));for(const retention of ['0','31','7\n','01'])assert.throws(()=>prepare({...f.options,retention}));
 for(const patch of [{runId:'1\nname=attack'},{attempt:'0'}])assert.throws(()=>prepare({...f.options,upload:'true',...patch}));assert.deepEqual(fs.readdirSync(f.root),['input']);
});
