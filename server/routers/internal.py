import logging
import ioc_extractor
import email_analyzer
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, status
from sqlalchemy.orm import Session
from dependencies import get_db
from database import crud, models, schemas
from database.database import engine
from database.schemas import ModuleSettingsSchema, ModuleSettingsCreateSchema
from typing import Dict, Any


router = APIRouter()
models.Base.metadata.create_all(bind=engine)


@router.post('/api/apikeys/', response_model=schemas.ApikeySchema, tags=['VitOSINT modules'], status_code=status.HTTP_201_CREATED)
def create_apikey(apikey, db=Depends(get_db)):
    existing_apikey = crud.get_apikey(db, apikey.name)

    if existing_apikey['name'] == 'None':
        db_apikey = crud.create_apikey(db, apikey)

        logging.info(f'Added API key: {apikey}')

        return db_apikey.to_dict()

    logging.error(f'Could not add API key. API key already exists: {apikey}')

    raise HTTPException(status_code=409, detail='Apikey already exists')


@router.delete('/api/apikeys', response_model=schemas.DeleteApikeyResponse, tags=['VitOSINT modules'])
def delete_apikey(name, db=Depends(get_db)):
    apikey = crud.get_apikey(db, name)

    if apikey['name'] == 'None' or not apikey:
        logging.error('Could not delete API key: API key not found')

        raise HTTPException(status_code=404, detail='API key not found')

    crud.delete_apikey(db=db, name=name)

    logging.info('Deleted API key: ' + name)

    return schemas.DeleteApikeyResponse(apikey=schemas.ApikeySchema(**apikey), message='API key deleted successfully')


@router.get('/api/apikeys/', response_model=list[schemas.ApikeySchema], tags=['VitOSINT modules'])
def read_apikeys(db=Depends(get_db)):
    apikeys = crud.get_apikeys(db)

    if not apikeys:
        logging.error('Could not get API keys: No API keys found')

        raise HTTPException(status_code=404, detail='No API keys found')

    return [apikey.to_dict() for apikey in apikeys]


@router.get('/api/apikeys', response_model=schemas.ApikeySchema, tags=['VitOSINT modules'])
def read_apikey(name, db=Depends(get_db)):
    apikey = crud.get_apikey(db, name)

    if apikey is None:
        logging.error('Could not get API key. API key not found: ' + name)

        raise HTTPException(status_code=404, detail='Apikey not found')

    return apikey


@router.get('/api/apikeys/is_active', response_model=Dict[str, Any], tags=['VitOSINT modules'])
def get_all_apikeys_is_active(db=Depends(get_db)):
    apikeys = crud.get_apikeys(db)

    return {apikey.name: apikey.is_active for apikey in apikeys}


@router.get('/api/apikeys/{name}/is_active', response_model=bool, tags=['VitOSINT modules'])
def get_apikey_is_active(name, db=Depends(get_db)):
    apikey = crud.get_apikey(db, name)

    if apikey is None:

        raise HTTPException(status_code=404, detail='Apikey not found')
    return apikey['is_active']


@router.put('/api/apikeys/{name}/is_active', response_model=schemas.ApikeyStateResponse, tags=['VitOSINT modules'])
def update_apikey_is_active(name, is_active, db=Depends(get_db)):
    apikey = crud.get_apikey(db, name)

    if apikey is None:
        raise HTTPException(status_code=404, detail='Apikey not found')

    apikey['is_active'] = is_active

    db.commit()

    return schemas.ApikeySchema(**apikey)


@router.post('/api/extractor/', tags=['VitOSINT modules'])
async def create_file(file=File()):
    return ioc_extractor.extract_iocs(file)


@router.post('/api/mailanalyzer/', tags=['VitOSINT modules'])
async def create_upload_file(file):
    return email_analyzer.analyze_email(file.file.read())


@router.get('/api/settings/modules/', response_model=list[schemas.ModuleSettingsSchema], tags=['VitOSINT modules'])
def read_module_settings(db=Depends(get_db)):
    settings = crud.get_all_modules_settings(db)

    if not settings:
        raise HTTPException(status_code=404, detail='No settings found')

    return [setting.to_dict() for setting in settings]


@router.post('/api/settings/modules/', response_model=ModuleSettingsCreateSchema, tags=['VitOSINT modules'])
def create_module_setting(setting, db=Depends(get_db)):
    return crud.create_module_setting(db=db, settings=setting)


@router.put('/api/settings/modules', response_model=ModuleSettingsSchema, tags=['VitOSINT modules'])
def update_module_setting(module_setting_input, db = Depends(get_db)):
    module_setting = crud.get_specific_module_setting(db=db, module_name=module_setting_input.name)

    if not module_setting:
        return crud.create_module_setting(db=db, settings=module_setting_input)

    return crud.update_module_setting(db=db, setting=module_setting, setting_input=module_setting_input)


@router.post('/api/settings/modules/disable/', response_model=ModuleSettingsSchema, tags=['VitOSINT modules'])
def disable_setting(module_name, db=Depends(get_db)):
    module_setting = crud.disable_module(db=db, module_name=module_name)

    if not module_setting:
        raise HTTPException(status_code=404, detail='Module setting not found')

    module_setting.enabled = False

    db.commit()
    db.refresh(module_setting)

    return module_setting.to_dict()


@router.post('/api/settings/modules/enable/', response_model=ModuleSettingsSchema, tags=['VitOSINT modules'])
def enable_setting(module_name, db=Depends(get_db)):
    module_setting = crud.disable_module(db=db, module_name=module_name)

    if not module_setting:
        raise HTTPException(status_code=404, detail='Module setting not found')

    module_setting.enabled = True

    db.commit()
    db.refresh(module_setting)

    return module_setting.to_dict()


@router.delete('/api/settings/modules/{module_name}', response_model=ModuleSettingsSchema, tags=['VitOSINT modules'])
def delete_module_setting(module_name, db=Depends(get_db)):
    module_setting = crud.get_specific_module_setting(db=db, module_name=module_name)

    if not module_setting:
        raise HTTPException(status_code=404, detail='Module setting not found')

    return crud.delete_setting(db=db, setting_name=module_name)


@router.get('/api/settings/modules/newsfeed/', response_model=list[schemas.NewsfeedSettingsSchema], tags=['VitOSINT modules'])
def read_newsfeed_settings(db=Depends(get_db)):
    settings = crud.get_newsfeed_settings(db)

    if not settings:
        raise HTTPException(status_code=404, detail='No settings found')

    return [setting.to_dict() for setting in settings]


@router.put('/api/settings/modules/newsfeed/', response_model=schemas.NewsfeedSettingsSchema, tags=['VitOSINT modules'])
def update_newsfeed_settings(settings, db=Depends(get_db)):
    updated_settings = crud.update_newsfeed_settings(db, settings.name, settings)

    return updated_settings


@router.delete('/api/settings/modules/newsfeed/{id}', response_model=schemas.NewsfeedSettingsSchema, tags=['VitOSINT modules'])
def delete_newsfeed_settings(id, db=Depends(get_db)):
    deleted_newsfeed = crud.delete_newsfeed_settings(db, id)

    if not deleted_newsfeed:
        raise HTTPException(status_code=404, detail='Newsfeed not found')

    return {'Success': 'Newsfeed deleted'}


@router.post('/api/settings/modules/newsfeed/enable', response_model=schemas.NewsfeedSettingsSchema, tags=['VitOSINT modules'])
def enable_newsfeed(feedName, db=Depends(get_db)):
    newsfeed_state = crud.disable_feed(db=db, feedName=feedName)

    if not newsfeed_state:
        raise HTTPException(status_code=404, detail='Newsfeed not found')

    newsfeed_state.enabled = True

    db.commit()
    db.refresh(newsfeed_state)

    return newsfeed_state.to_dict()


@router.post('/api/settings/modules/newsfeed/disable', response_model=schemas.NewsfeedSettingsSchema, tags=['VitOSINT modules'])
def disable_newsfeed(feedName, db=Depends(get_db)):
    newsfeed_state = crud.disable_feed(db=db, feedName=feedName)

    if not newsfeed_state:
        raise HTTPException(status_code=404, detail='Newsfeed not found')

    newsfeed_state.enabled = False
    
    db.commit()
    db.refresh(newsfeed_state)

    return newsfeed_state.to_dict()
