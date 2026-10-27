import test from 'node:test';
import assert from 'node:assert/strict';
import { completeChoices, buildResolutions } from './sync-choice.mjs';
test('no conflict may be omitted, including delete/edit confirmation', () => {
 const rows = [{id:'a',kind:'edit_edit'}, {id:'b',kind:'delete_edit'}];
 const choices = { a:{choice:'local',confirm_delete_edit:false}, b:{choice:'both',confirm_delete_edit:false} };
 assert.equal(completeChoices(rows, choices), false);
 assert.throws(() => buildResolutions(rows, choices));
 choices.b.confirm_delete_edit = true;
 assert.equal(completeChoices(rows, choices), true);
 assert.equal(buildResolutions(rows, choices).length, 2);
 delete choices.a;
 assert.equal(completeChoices(rows, choices), false);
});
test('only local/remote/both are valid; empty preview can commit', () => {
 assert.equal(completeChoices([{id:'x',kind:'edit_edit'}], {x:{choice:'',confirm_delete_edit:false}}), false);
 assert.deepEqual(buildResolutions([], {}), []);
});
