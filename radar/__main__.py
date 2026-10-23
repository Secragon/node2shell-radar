import sys


if "--cli" in sys.argv:
    from radar.cli import main
    sys.argv.remove("--cli")
else:
    from radar.gui import main

raise SystemExit(main())
