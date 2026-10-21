"""
NIGHTWATCH Forwarder Agent — Native Windows Service
Integrates with the Windows Service Control Manager (SCM) via win32serviceutil.
Provides start, stop, shutdown, and pause lifecycle handlers.
"""

import logging
import os
import sys
from pathlib import Path

# Ensure root path is accessible
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    HAS_WIN32SERVICE = True
except ImportError:
    HAS_WIN32SERVICE = False

from forwarder.agent.config import AgentConfig
from forwarder.agent.service import ForwarderAgentService

logger = logging.getLogger("nightwatch.forwarder.windows_service")


if HAS_WIN32SERVICE:
    class NightwatchWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "NightwatchAgent"
        _svc_display_name_ = "NIGHTWATCH Telemetry Forwarder Agent"
        _svc_description_ = "Collects genuine Windows Event Logs and securely transmits them to central NIGHTWATCH receiver."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.agent_service = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            servicemanager.LogInfoMsg("Stopping NIGHTWATCH Forwarder Service...")
            if self.agent_service:
                self.agent_service.stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PKEY_INFO_TYPE,
                ("NIGHTWATCH Forwarder Service starting...", "")
            )

            # Determine config path
            config_env = os.environ.get("NIGHTWATCH_CONFIG")
            if config_env and os.path.exists(config_env):
                cfg_path = config_env
            else:
                default_path = Path("C:/ProgramData/Nightwatch/agent.json")
                if default_path.exists():
                    cfg_path = str(default_path)
                else:
                    cfg_path = str(Path(__file__).resolve().parent.parent.parent / "config" / "agent.example.json")

            try:
                config = AgentConfig.from_file(cfg_path)
                config.resolve_paths(Path(cfg_path).parent)
                self.agent_service = ForwarderAgentService(config)
                self.agent_service.start()

                # Wait until SCM sends stop signal
                win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            except Exception as e:
                servicemanager.LogErrorMsg(f"FATAL error in NIGHTWATCH Service: {e}")
                raise


def main():
    if not HAS_WIN32SERVICE:
        print("Error: pywin32 (win32serviceutil) is required to run as a Windows Service.", file=sys.stderr)
        print("To run in foreground: python -m forwarder.agent.main --config <path-to-config>", file=sys.stderr)
        sys.exit(1)

    win32serviceutil.HandleCommandLine(NightwatchWindowsService)


if __name__ == "__main__":
    main()
