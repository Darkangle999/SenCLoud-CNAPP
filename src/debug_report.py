import sys
from odineyes.db.session import get_sessionmaker
from odineyes.api.inventory_routes import get_compliance_report

try:
    print(get_compliance_report(account_id=2, frameworks='CIS,SOC2'))
except Exception as e:
    import traceback
    traceback.print_exc()
