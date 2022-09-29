package fork

type ProcessOpt = func(p *BackgroundProcess)

func WithArgs(args ...string) ProcessOpt {
	return func(p *BackgroundProcess) {
		p.cmd.Args = append(p.cmd.Args, args...)
	}
}
