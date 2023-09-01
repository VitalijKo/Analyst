import React from 'react';
import { useState, useEffect } from 'react';
import { atom, useSetRecoilState } from 'recoil';
import api from './api';
import { createTheme, ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Main from './Main';

export const apiKeysState = atom({
  key: 'KeysState',
  default: []
});

export const modulesState = atom({
  key: 'ModulesState',
  default: []
});

export const newsfeedState = atom({
  key: 'NewsfeedState',
  default: []
});

export const newsfeedListState = atom({
  key: 'NewsfeedListState',
  default: []
});

function App() {
  const [apikeyLoaded, setApikeyLoaded] = useState(false);
  const [modulesLoaded, setModulesLoaded] = useState(false);
  const [newsfeedListLoaded, setNewsfeedListLoaded] = useState(false);

  const setApiKeys = useSetRecoilState(apiKeysState);
  const setModules = useSetRecoilState(modulesState);
  const setNewsfeedList = useSetRecoilState(newsfeedListState);

  const getDesignTokens = () => ({
    palette: {
      mode: 'dark',
      ...({
        primary: {
          main: '#cf000f'
        },
        typography: {
          htmlFontSize: 16
        },
        background: {
          default: '#111',
          card: '#000',
          cvssCard: '#000',
          cvssCircle: '#000',
          textfieldlarge: '#000',
          uploadarea: '#111',
          tableheader: 'whitesmoke',
          tablecell: 'white',
          tableborder: '#000'
        },
        components: {
          MuiCard: {
            variants: [
              {
                props: {
                  variant: 'primary'
                },
                style: {
                  backgroundColor: '#000',
                  minWidth: '450px',
                  minHeight: '300px',
                  maxWidth: '1450px',
                  margin: '30px auto',
                  border: '1px solid rgb(192, 192, 192)',
                  padding: '30px',
                  borderRadius: 5,
                  overflow: 'auto',
                  boxShadow: '5'
                }
              },
              {
                props: {
                  variant: 'secondary'
                },
                style: {
                  backgroundColor: '#000',
                  borderRadius: 5,
                  boxShadow: 0,
                  m: 2,
                  p: 2
                }
              }
            ]
          }
        }
      })
    }
  });

  const theme = createTheme(getDesignTokens());

  useEffect(() => {
    api.get('/api/apikeys/is_active').then((response) => {
      const result = response.data;

      setApiKeys(result);
      setApikeyLoaded(true);
    });

    api.get('/api/settings/modules/').then((response) => {
      const result = response.data.reduce((dict, item) => {
        const { name, ...rest } = item;
        dict[name] = rest;

        return dict;
      }, {});

      setModules(result);
      setModulesLoaded(true);
    });

    api.get('/api/settings/modules/newsfeed/').then((response) => {
      const result = response.data.reduce((dict, item) => {
        const { name, ...rest } = item;

        dict[name] = rest;

        return dict;
      }, {});

      setNewsfeedList(result);
      setNewsfeedListLoaded(true);
    });
  }, [setApiKeys, setModules, setNewsfeedList]);

  if (
    modulesLoaded &&
    apikeyLoaded &&
    newsfeedListLoaded
  ) {
    return (
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Main />
      </ThemeProvider>
    );
  }
}

export default App;
