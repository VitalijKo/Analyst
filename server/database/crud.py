from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from .models import Apikey, ModuleSettings, NewsfeedSettings
from .schemas import ApikeySchema, NewsfeedSettingsSchema, ModuleSettingsCreateSchema


def create_apikey(db: Session, apikey: ApikeySchema):
    db_apikey = Apikey(**apikey.dict())
    db.add(db_apikey)
    db.commit()
    db.refresh(db_apikey)

    return db_apikey


def get_apikeys(db, skip=0, limit=100):
    return db.query(Apikey).offset(skip).limit(limit).all()


def get_apikey(db, name):
    key = db.query(Apikey).filter(Apikey.name == name).first()

    if key:
        return key.to_dict()

    return {'name': 'None', 'key': '', 'is_active': False}


def delete_apikey(db, name):
    db_apikey = db.query(Apikey).filter(Apikey.name == name).first()
    db.delete(db_apikey)
    db.commit()


def get_all_modules_settings(db):
    return db.query(ModuleSettings).all()


def get_specific_module_setting(db, module_name):
    return db.query(ModuleSettings).filter(ModuleSettings.name == module_name).first()


def update_module_setting(db, setting, setting_input):
    setattr(setting, 'name', setting_input.name)
    setattr(setting, 'description', setting_input.description)
    setattr(setting, 'enabled', setting_input.enabled)

    db.add(setting)
    db.commit()
    db.refresh(setting)

    return setting


def disable_module(db, module_name):
    setting = db.query(ModuleSettings).filter(ModuleSettings.name == module_name).first()

    setattr(setting, 'enabled', False)

    db.add(setting)
    db.commit()
    db.refresh(setting)

    return setting


def create_module_setting(db, settings):
    data = ModuleSettings(
        name=settings.name,
        description=settings.description,
        enabled=True
    )

    db.add(data)
    db.commit()
    db.refresh(data)

    return data.to_dict()


def delete_setting(db, setting_name):
    setting = db.query(ModuleSettings).filter(ModuleSettings.name == setting_name).first()

    db.delete(setting)
    db.commit()

    return setting


def get_newsfeed_settings(db, skip=0, limit=100):
    return db.query(NewsfeedSettings).offset(skip).limit(limit).all()


def create_newsfeed_settings(db, settings):
    db_settings = NewsfeedSettings(**settings.dict())
    db.add(db_settings)
    db.commit()
    db.refresh(db_settings)

    return db_settings


def update_newsfeed_settings(db, name, settings):
    db_settings = db.query(NewsfeedSettings).filter(NewsfeedSettings.name == name).first()

    if db_settings:
        db_settings.name = settings.name
        db_settings.url = settings.url
        db_settings.icon = settings.icon
        db_settings.enabled = settings.enabled
        db.commit()
        db.refresh(db_settings)

        return db_settings

    create_newsfeed_settings(db, settings)

    return db_settings


def delete_newsfeed_settings(db, id):
    db_settings = db.query(NewsfeedSettings).filter(NewsfeedSettings.name == id).first()

    if db_settings:
        db.delete(db_settings)
        db.commit()

        return True


def disable_feed(db, feedName):
    setting = db.query(NewsfeedSettings).filter(NewsfeedSettings.name == feedName).first()

    setattr(setting, 'enabled', False)

    db.add(setting)
    db.commit()
    db.refresh(setting)
    
    return setting
