package acmeissuer

import "golang.org/x/sys/unix"

// EVFILT_PROC observes an owned child's exit while leaving it waitable. ESRCH
// during registration means the child exited before the filter was installed;
// no other waiter can have reaped this command in the meantime.
func observeExit(pid int) error {
	queue, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(queue)
	unix.CloseOnExec(queue)
	var change unix.Kevent_t
	unix.SetKevent(&change, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change.Fflags = unix.NOTE_EXIT
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(queue, []unix.Kevent_t{change}, events, nil)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ESRCH {
			return nil
		}
		if err != nil {
			return err
		}
		if n != 1 {
			continue
		}
		if events[0].Flags&unix.EV_ERROR != 0 {
			if events[0].Data == int64(unix.ESRCH) {
				return nil
			}
			return unix.Errno(events[0].Data)
		}
		if events[0].Fflags&unix.NOTE_EXIT != 0 {
			return nil
		}
	}
}
