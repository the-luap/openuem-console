# Legacy profile deletion

Deleting a desktop task profile now requires current server-administrator
authority and its exact selected global, organization or site audience. The
dedicated DELETE handler checks these before any legacy editor read. Foreign,
ambiguous or moved profiles cannot be deleted through the current scope's URL.

The profile, its tasks, related stored task reports and audience/tag associations
are removed in one transaction. Shared tags and other profiles' independent
tasks/results remain. This preserves the existing deletion semantics while
removing the former gap between task deletion and profile deletion. If deleting
the parent profile or writing its audit fails, all earlier task and report
deletions roll back. Cancellation has the same effect.

The ten-second transaction acquires the shared profile authority checks and a
write-compatible lock on the complete audience tables before reading the target.
Permission, organization/site, audience, profile and deleted child locks remain
held through audit commit. A concurrent task or result cannot be attached to a
profile being deleted. A second delete through the old URL returns not found.

The review page verifies the current scope separately, shows the profile name
and ID, and explains that tasks and stored results will be deleted. Very long
legacy names are shortened to 512 characters with an explicit notice and the
full numeric ID. This bounds the displayed name without making an existing long
name impossible to delete. Reviewing or canceling does not remove anything.
The list's review link and the confirmation controls work with the keyboard.

Bundled HTMX sends the confirmation as an empty DELETE with the inherited CSRF
header. The endpoint accepts that request without requiring a form content type;
it rejects body/query values and alternative target fields. The existing
production CSRF/origin checks and pre-parsing wire limit apply. Cancellation is
a GET back to the current scope's profile list.

Audit migration 20 adds inventory.profiles.delete, with the original scope,
actor and profileID/tasks/deletedTaskCount reference. The event is retained
after deletion and participates in existing scoped audit browsing, export and
retention. Global events remain visible only to server administrators. Apply the
migration and stop older console writers before using the new delete path.
The direct model deletion method has been removed.

Owned PostgreSQL/race tests cover all three scopes, roles, unchanged reviews,
foreign data preservation, actual task/issue/report cascades, retained shared
tags, name bounds, changed audience, parent-deletion failure, audit failure,
cancellation and final transaction locks. Actual registered console tests
reproduce and reject the former foreign-organization deletion, exercise empty
DELETE without a content type, and check CSRF, strict fields, the review page,
saved deletion state and retained audit. Real component/browser tests cover
confirmation and cancellation at 390, 768 and 1440 pixels, including long names.

Deletion does not send an undo or cancellation command to devices. It does not
provide immutable review tokens or revision conflict detection: the confirmed
action removes the current profile and its current tasks in the verified scope.
Profile creation, cloning, other editor reads and task lifecycle work remain
separate workflows.
