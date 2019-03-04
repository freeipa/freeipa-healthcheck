#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import dbus


# Not registered on purpose
class SystemdService:
    service_name = None

    def __init__(self):
        pass

    def get_service(self):
        service_name = self.service_name
        if not service_name.endswith('.service'):
            service_name += '.service'
        bus = dbus.SystemBus()
        systemd1_obj = bus.get_object(
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1'
        )
        manager_if = dbus.Interface(
            systemd1_obj, 'org.freedesktop.systemd1.Manager'
        )
        try:
            unit_path = manager_if.GetUnit(service_name)
        except dbus.DBusException as e:
            return vars(e)
        service_obj = bus.get_object('org.freedesktop.systemd1', unit_path)
        unit_if = dbus.Interface(
            service_obj, 'org.freedesktop.systemd1.Unit'
        )
        service_if = dbus.Interface(
            service_obj, 'org.freedesktop.systemd1.Service'
        )
        prop_if = dbus.Interface(
            service_obj, 'org.freedesktop.DBus.Properties'
        )
        properties = {}
        for k, v in prop_if.GetAll(unit_if.dbus_interface).items():
            properties[str(k)] = v
        for k, v in prop_if.GetAll(service_if.dbus_interface).items():
            properties[str(k)] = v
        return properties

    def check_service(self):
        properties = self.get_service()
        error = properties.get('_dbus_error_name')
        if error:
            return False, error
        loaded = properties['LoadState'] == 'loaded'
        active = properties['ActiveState'] == 'active'
        return loaded and active, None
