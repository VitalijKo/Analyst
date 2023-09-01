from pydantic import BaseModel, validator


class ApikeySchema(BaseModel):
    name: str
    key: str = ''
    is_active: bool = False


class DeleteApikeyResponse(BaseModel):
    apikey: ApikeySchema
    message: str


class ApikeyStateResponse(BaseModel):
    name: str


class ModuleSettingsSchema(BaseModel):
    name: str
    description: str = ''
    enabled: bool

    class Config:
        orm_mode = True


class ModuleSettingsCreateSchema(BaseModel):
    name: str
    description: str = ''
    enabled: bool


class ModuleSettingsStatusSchema(BaseModel):
    enabled: bool


class NewsfeedSettingsSchema(BaseModel):
    name: str
    url: str
    icon: str
    enabled: bool

    class Config:
        orm_mode = True


class NewsfeedSettingsCreateSchema(BaseModel):
    name: str
    url: str
    enabled: bool
