import React from 'react';
import { atom, useSetRecoilState, useRecoilValue } from 'recoil';
import PropTypes from 'prop-types';
import ApiKeys from './ApiKeys';
import Modules from './Modules';
import Card from '@mui/material/Card';
import Tab from '@mui/material/Tab';
import Tabs from '@mui/material/Tabs';

export const settingsTabIndex = atom({
    key: 'SettingsTabIndexState',
    default: 0
});

export default function Settings() {
    const cardStyle = { p: 5, pt: 2, boxShadow: '0' };

    function SettingsTabPanel(props) {
        const { children, value, index, ...other } = props;

        return (
            <div
        role='tabpanel'
        hidden={value !== index}
        id={`settings-tabpanel-${index}`}
        key={`settings-tabpanel-${index}`}
        aria-labelledby={`settings-tab-${index}`}
        {...other}
      >
        {value === index && <div>{children}</div>}
      </div>
        );
    }

    SettingsTabPanel.propTypes = {
        children: PropTypes.node,
        index: PropTypes.number.isRequired,
        value: PropTypes.number.isRequired
    };

    const tabIndex = useRecoilValue(settingsTabIndex);
    const setTabIndex = useSetRecoilState(settingsTabIndex);
    const handleTabIndexChange = (event, newIndex) => {
        setTabIndex(newIndex);
    };

    return (
        <div>
      <Tabs
        value={tabIndex}
        onChange={handleTabIndexChange}
        orientation='vertical'
        style={{ float: 'left' }}
      >
        <Tab label='API Keys' />
        <Tab label='Modules' />
      </Tabs>
      <SettingsTabPanel value={tabIndex} index={0}>
        <Card sx={cardStyle}>
          <ApiKeys />
        </Card>
      </SettingsTabPanel>
      <SettingsTabPanel value={tabIndex} index={1}>
        <Card sx={cardStyle}>
          <Modules />
        </Card>
      </SettingsTabPanel>
    </div>
    );
}
