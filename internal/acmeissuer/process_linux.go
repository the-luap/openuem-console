package acmeissuer

import "golang.org/x/sys/unix"

func observeExit(pid int) error {
	var information unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &information, unix.WEXITED|unix.WNOWAIT, nil)
		if err != unix.EINTR {
			return err
		}
	}
}
