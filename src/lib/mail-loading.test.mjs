import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import {mailMessageKey,mergeMailInbox} from './mail-inbox.mjs';
const source=readFileSync(new URL('../App.vue',import.meta.url),'utf8');
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const ref=value=>({value});
const fn=(start,end)=>source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start)));
function setup(api={}) {
 const state={mailAccounts:ref([{id:'a',email:'a@test',supported:true},{id:'b',email:'b@test',supported:true}]),mailAccountId:ref('a'),mailUnified:ref(true),mailFolderName:ref('INBOX'),mailFilter:ref('all'),mailAppliedKeyword:ref(''),mailKeyword:ref(''),mailFolders:ref([]),mailRole:ref('inbox'),mailOtherFolder:ref(''),mailFoldersBusy:ref(false),mailMessages:ref([]),mailCacheCached:ref(false),mailCacheAt:ref(''),mailBusy:ref(false),mailChecking:ref(false),mailSearchNote:ref(''),mailError:ref(''),mailOlderError:ref(''),mailCursor:ref(-1),mailSeq:1,mailPageEnds:new Map(),mailMessageVersions:new Map(),mailRemovedKeys:new Set(),mailMessageKey,mergeMailInbox,normalizeMailList:r=>Array.isArray(r)?{messages:r,cached:false,fetchedAt:null}:r,warmMailBodies:()=>{},loadMailFolders:()=>new Promise(()=>{}),resetMailMessages:()=>{},api:{mailList:async()=>[],...api}};
 const script=fn('async function fetchMailRows(', '/** Folder list for the current account.')+fn('async function loadMail(', 'async function loadOlderMail()')+fn('async function selectMailAccount(', '/** 聚合只读取');
 const context=vm.createContext(state);vm.runInContext(ts.transpileModule(script+'\nglobalThis.actions={fetchMailRows,loadMail,selectMailAccount}',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText,context);
 return {...state,...context.actions,context};
}
const row=uid=>({uid,from:'sender',subject:'mail',date:'2026-11-15',seen:false});
test('cached account paints before another account live request finishes',async()=>{
 const slow=deferred();const state=setup({mailList:async(id,_folder,options)=>options.cacheOnly?(id==='a'?[row(1)]:[]):id==='b'?slow.promise:[row(2)]});
 const work=state.loadMail();await flush();assert.equal(state.mailBusy.value,false);assert.equal(state.mailChecking.value,true);assert.ok(state.mailMessages.value.some(m=>m.uid===1));assert.ok(state.mailMessages.value.some(m=>m.uid===2));slow.resolve([]);await work;assert.equal(state.mailChecking.value,false);
});
test('inbox loading never waits for remote folder discovery',async()=>{
 const state=setup({mailList:async()=>[row(3)]});await state.selectMailAccount({id:'a',supported:true});assert.equal(state.mailMessages.value[0].uid,3);
});
test('old account responses never append after a view switch',async()=>{
 const pending=deferred();const state=setup({mailList:async(_id,_folder,options)=>options.cacheOnly?[]:pending.promise});const work=state.loadMail();await flush();state.context.mailSeq+=1;pending.resolve([row(5)]);await work;assert.equal(state.mailMessages.value.length,0);
});
test('cached messages remain visible when all live connections fail',async()=>{
 const state=setup({mailList:async(_id,_folder,options)=>{if(options.cacheOnly)return [row(1)];throw Error('offline')}});await state.loadMail();assert.equal(state.mailMessages.value.length,2);assert.equal(state.mailBusy.value,false);assert.ok(state.mailError.value);
});
