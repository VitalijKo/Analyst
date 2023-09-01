import os
import logging
import default_strings
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import internal, external
from sqlalchemy.orm import Session
from database import models
from database.database import SessionLocal, engine
from database.models import ModuleSettings, NewsfeedSettings

models.Base.metadata.create_all(bind=engine)

allowed_origins = os.getenv('ALLOWED_ORIGINS', '*')

description = '## VitOSINT interactive API documentation'

tags_metadata = [
    {
        'name': 'IP addresses',
        'description': 'Services to analyze IP addresses.'
    },
    {
        'name': 'URLs',
        'description': 'Services to analyze IP addresses.'
    },
    {
        'name': 'Domains',
        'description': 'Services to analyze domains.'
    },
    {
        'name': 'Hashes',
        'description': 'Services to analyze hashes.'
    },
    {
        'name': 'Emails',
        'description': 'Services to analyze emails.'
    },
    {
        'name': 'Social Media',
        'description': 'Search social media.'
    },
    {
        'name': 'Multi',
        'description': 'Services that can search for multiple IoC types.'
    },
    {
        'name': 'CVEs',
        'description': 'Search for vulnerabilities in form of CVE IDs.'
    },
    {
        'name': 'VitOSINT modules',
        'description': 'Internal VitOSINT modules.'
    }
]

app = FastAPI(
    title='VitOSINT',
    description=description,
    version='1.0.0',
    openapi_tags=tags_metadata
)

app.include_router(internal.router)
app.include_router(external.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins.split(','),
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*']
)


def add_default_module_settings(db):
    default_settings = [
        ModuleSettings(
            name='Newsfeed',
            description='',
            enabled=True
        ),
        ModuleSettings(
            name='IOC Analyzer',
            description=default_strings.ioc_analyzer['description'],
            enabled=True
        ),
        ModuleSettings(
            name='IOC Extractor',
            description=default_strings.ioc_extractor['description'],
            enabled=True
        ),
        ModuleSettings(
            name='Email Analyzer',
            description=default_strings.email_analyzer['description'],
            enabled=True
        ),
        ModuleSettings(
            name='Domain Monitoring',
            description=default_strings.domain_monitoring['description'],
            enabled=True
        ),
        ModuleSettings(
            name='CVSS Calculator',
            description='',
            enabled=True
        )
    ]

    for default in default_settings:
        existing_setting = db.query(ModuleSettings).filter(ModuleSettings.name == default.name).first()

        if existing_setting:
            pass

        else:
            new_setting = ModuleSettings(
                name=default.name,
                description=default.description,
                enabled=default.enabled
            )
            db.add(new_setting)

    db.commit()

    logging.info('Created default module settings')


def add_default_newsfeeds(db):
    default_newsfeeds = [
        NewsfeedSettings(
            name='Computerworld',
            url='https://www.computerworld.com/category/security/feed',
            icon='computerworld',
            enabled=True
        ),
        NewsfeedSettings(
            name='CyberScoop',
            url='https://www.cyberscoop.com/news/threats/feed',
            icon='cyberscoop',
            enabled=True
        ),
        NewsfeedSettings(
            name='Dark Reading',
            url='https://www.darkreading.com/rss_simple.asp',
            icon='darkreading',
            enabled=True
        ),
        NewsfeedSettings(
            name='HackerNoon',
            url='https://hackernoon.com/tagged/cybersecurity/feed',
            icon='hackernoon',
            enabled=True
        ),
        NewsfeedSettings(
            name='Helpnet Security',
            url='https://www.helpnetsecurity.com/feed/',
            icon='helpnetsecurity',
            enabled=True
        ),
        NewsfeedSettings(
            name='Krebs on Security',
            url='https://krebsonsecurity.com/feed/',
            icon='krebsonsecurity',
            enabled=True
        ),
        NewsfeedSettings(
            name='Security Magazine',
            url='https://www.securitymagazine.com/rss/topic/2236',
            icon='securitymagazine',
            enabled=True
        ),
        NewsfeedSettings(
            name='SecurityWeek',
            url='https://feeds.feedburner.com/securityweek',
            icon='securityweek',
            enabled=True
        ),
        NewsfeedSettings(
            name='TechCrunch',
            url='https://techcrunch.com/category/security/feed',
            icon='techcrunch',
            enabled=True
        ),
        NewsfeedSettings(
            name='The Hacker News',
            url='https://feeds.feedburner.com/TheHackersNews',
            icon='thehackernews',
            enabled=True
        ),
        NewsfeedSettings(
            name='threatpost',
            url='https://threatpost.com/feed/',
            icon='threatpost',
            enabled=True
        ),
        NewsfeedSettings(
            name='The Record',
            url='https://therecord.media/feed',
            icon='therecord',
            enabled=True
        ),
        NewsfeedSettings(
            name='The Register',
            url='https://www.theregister.co.uk/security/headlines.atom',
            icon='theregister',
            enabled=True
        ),
        NewsfeedSettings(
            name='The Verge',
            url='https://www.theverge.com/rss/cyber-security/index.xml',
            icon='theverge',
            enabled=True
        ),
        NewsfeedSettings(
            name='Wired',
            url='https://www.wired.com/feed/category/security/latest/rss',
            icon='wired',
            enabled=True
        ),
        NewsfeedSettings(
            name='ZDNet',
            url='https://www.zdnet.com/topic/security/rss.xml',
            icon='zdnet',
            enabled=True
        )
    ]

    for feed in default_newsfeeds:
        existing_feed = db.query(NewsfeedSettings).filter(NewsfeedSettings.name == feed.name).first()

        if not existing_feed:
            new_feed = NewsfeedSettings(
                name=feed.name,
                url=feed.url,
                icon=feed.icon,
                enabled=feed.enabled
            )

            db.add(new_feed)

    db.commit()
    
    logging.info('Created default newsfeeds')


@app.on_event('startup')
async def startup_event():
    db = SessionLocal()
    add_default_module_settings(db)
    add_default_newsfeeds(db)
