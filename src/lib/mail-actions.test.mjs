import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import {mailMessageKey} from './mail-inbox.mjs';
const source = readFileSync(new URL('../App.vue', import.meta.url), 'utf8');
const section = source.slice(source.indexOf('function applyMailSeen('), source.indexOf('function mailSenderName('));
const ref = value => ({value});
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b;}); return {promise,resolve,reject}; };
function setup(api = {}) {
  const row = {entryId:'a',folder:'INBOX',uid:1,seen:true,subject:'test'};
  const state = {mailSelected:ref(row),mailMessages:ref([row]),mailFolders:ref([{name:'INBOX',role:'inbox',unread:2}]),mailUnified:ref(false),mailAccountId:ref('a'),mailRoleCounts:ref({inbox:2}),mailMutationBusy:ref(''),mailMutationError:ref(''),mailBodyBusy:ref(false),mailDeleteTarget:ref(row),mailFilter:ref('all'),status:ref({unlocked:true}),mailCursor:ref(0),mailSyncNote:ref(''),mailMessageVersions:new Map(),mailRemovedKeys:new Set(),mailSeq:1,mailMessageKey,refreshMailCounts:()=>{},api:{mailSetSeen:async()=>{},mailDelete:async()=>{},...api}};
  state.backToMailList=()=>{state.mailSelected.value=null;state.mailDeleteTarget.value=null;};
  const context=vm.createContext(state);
  vm.runInContext(ts.transpileModule(section+'\nglobalThis.actions={toggleMailSeen,deleteMailMessage};',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.None}}).outputText,context);
  return {...state,...context.actions,context,row};
}
test('desktop seen mutation commits only after server success and uses complete source', async()=>{
 const pending=deferred();let args;const s=setup({mailSetSeen:(...a)=>{args=a;return pending.promise;}});
 const work=s.toggleMailSeen();assert.equal(s.row.seen,true);assert.deepEqual(args,['a',1,false,'INBOX']);
 await s.toggleMailSeen();pending.resolve();await work;assert.equal(s.row.seen,false);assert.equal(s.mailFolders.value[0].unread,3);assert.equal(s.mailMutationBusy.value,'');
});
test('desktop failed write leaves unread state and count intact',async()=>{
 const s=setup({mailSetSeen:async()=>{throw Error('offline');}});await s.toggleMailSeen();assert.equal(s.row.seen,true);assert.equal(s.mailFolders.value[0].unread,2);assert.match(s.mailMutationError.value,/offline/);
});
test('desktop old-account completion does not update new view',async()=>{
 const pending=deferred();const s=setup({mailSetSeen:()=>pending.promise});const work=s.toggleMailSeen();s.context.mailSeq=2;s.mailAccountId.value='b';pending.resolve();await work;assert.equal(s.row.seen,true);assert.equal(s.mailFolders.value[0].unread,2);
});
test('desktop delete requires a confirmation target and ignores same UID in another account',async()=>{
 let calls=0;const s=setup({mailDelete:async()=>{calls++;}});const other={...s.row,entryId:'b'};s.mailMessages.value.push(other);s.mailDeleteTarget.value=null;await s.deleteMailMessage();assert.equal(calls,0);s.mailDeleteTarget.value=s.row;await s.deleteMailMessage();assert.equal(calls,1);assert.equal(s.mailMessages.value.length,1);assert.equal(s.mailMessages.value[0],other);
});
test('desktop failed delete retains mail and confirmation for retry',async()=>{
 const s=setup({mailDelete:async()=>{throw Error('unsupported');}});await s.deleteMailMessage();assert.equal(s.mailMessages.value.length,1);assert.equal(s.mailDeleteTarget.value,s.row);assert.match(s.mailMutationError.value,/unsupported/);
});
