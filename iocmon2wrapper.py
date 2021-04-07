#!/var/www/MISP/venv/bin/python
from iocmon import IOCMONITOR

if __name__ == '__main__':
    misp_args={"to_ids":1, "published":1, "enforceWarninglist":1, "event_timestamp":"3d", "limit":2500}
    im=IOCMONITOR(args=misp_args, targetLogPlatform='Elastic', loginNecessary=True)
    im.mispSetup()
    im.checkForHits()
    im.sendReport(mailPerEvent=True)
