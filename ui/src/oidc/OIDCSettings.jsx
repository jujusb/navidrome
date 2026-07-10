import React, { useState, useEffect, useCallback } from 'react'
import {
  Title,
  useTranslate,
  useNotify,
  useRefresh,
} from 'react-admin'
import {
  Card,
  CardContent,
  CardActions,
  Button,
  TextField,
  FormControlLabel,
  Switch,
  Typography,
  CircularProgress,
  makeStyles,
} from '@material-ui/core'
import { baseUrl } from '../utils'

const useStyles = makeStyles(
  (theme) => ({
    card: {
      marginTop: '1em',
      maxWidth: 800,
    },
    form: {
      '& > *': {
        marginBottom: theme.spacing(2),
      },
    },
    field: {
      width: '100%',
    },
    section: {
      marginTop: theme.spacing(3),
      marginBottom: theme.spacing(1),
    },
    actions: {
      justifyContent: 'flex-end',
    },
  }),
  { name: 'NDOIDCSettings' },
)

const OIDCSettings = () => {
  const classes = useStyles()
  const translate = useTranslate()
  const notify = useNotify()
  const refresh = useRefresh()
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [config, setConfig] = useState({
    enabled: false,
    issuer: '',
    clientId: '',
    clientSecret: '',
    redirectUrl: '',
    scopes: ['openid', 'profile', 'email'],
    autoProvision: true,
    adminClaim: '',
    adminValue: '',
    groupsClaim: 'groups',
  })

  useEffect(() => {
    fetch(baseUrl('/api/oidc-config'), {
      headers: {
        Authorization: 'Bearer ' + localStorage.getItem('token'),
      },
    })
      .then((res) => res.json())
      .then((data) => {
        if (data && typeof data.enabled !== 'undefined') {
          setConfig(data)
        }
        setLoading(false)
      })
      .catch(() => {
        setLoading(false)
      })
  }, [])

  const handleChange = useCallback((field) => (e) => {
    const value = e.target.type === 'checkbox' ? e.target.checked : e.target.value
    setConfig((prev) => ({ ...prev, [field]: value }))
  }, [])

  const handleScopesChange = useCallback((e) => {
    setConfig((prev) => ({
      ...prev,
      scopes: e.target.value.split(',').map((s) => s.trim()),
    }))
  }, [])

  const handleSave = useCallback(() => {
    setSaving(true)
    fetch(baseUrl('/api/oidc-config'), {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + localStorage.getItem('token'),
      },
      body: JSON.stringify(config),
    })
      .then((res) => {
        if (!res.ok) throw new Error('Failed to save')
        notify('Configuration saved', { type: 'info' })
        refresh()
      })
      .catch((err) => {
        notify('Error saving configuration: ' + err.message, {
          type: 'warning',
        })
      })
      .finally(() => setSaving(false))
  }, [config, notify, refresh])

  if (loading) {
    return (
      <Card className={classes.card}>
        <CardContent style={{ textAlign: 'center', padding: '3em' }}>
          <CircularProgress />
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={classes.card}>
      <Title title="OIDC Authentication" />
      <CardContent>
        <Typography variant="h5" gutterBottom>
          OpenID Connect
        </Typography>
        <Typography variant="body2" color="textSecondary" gutterBottom>
          Configure single sign-on via an OpenID Connect provider (e.g., Keycloak, Authelia, Google).
        </Typography>

        <div className={classes.form}>
          <FormControlLabel
            control={
              <Switch
                checked={config.enabled}
                onChange={handleChange('enabled')}
                color="primary"
              />
            }
            label="Enable OIDC Authentication"
          />

          <Typography variant="subtitle1" className={classes.section}>
            Provider Configuration
          </Typography>

          <TextField
            className={classes.field}
            label="Issuer URL"
            value={config.issuer}
            onChange={handleChange('issuer')}
            placeholder="https://auth.example.com/realms/myrealm"
            helperText="The OIDC issuer URL (auto-discovery is used)"
            variant="outlined"
            size="small"
          />

          <TextField
            className={classes.field}
            label="Client ID"
            value={config.clientId}
            onChange={handleChange('clientId')}
            variant="outlined"
            size="small"
          />

          <TextField
            className={classes.field}
            label="Client Secret"
            value={config.clientSecret}
            onChange={handleChange('clientSecret')}
            type="password"
            variant="outlined"
            size="small"
            helperText="Leave as **** to keep the current value"
          />

          <TextField
            className={classes.field}
            label="Redirect URL"
            value={config.redirectUrl}
            onChange={handleChange('redirectUrl')}
            placeholder="http://localhost:4533/api/oauth/callback"
            variant="outlined"
            size="small"
          />

          <TextField
            className={classes.field}
            label="Scopes (comma-separated)"
            value={config.scopes ? config.scopes.join(', ') : 'openid, profile, email'}
            onChange={handleScopesChange}
            variant="outlined"
            size="small"
          />

          <Typography variant="subtitle1" className={classes.section}>
            User Provisioning
          </Typography>

          <FormControlLabel
            control={
              <Switch
                checked={config.autoProvision}
                onChange={handleChange('autoProvision')}
                color="primary"
              />
            }
            label="Auto-provision users (create on first login)"
          />

          <TextField
            className={classes.field}
            label="Admin Claim"
            value={config.adminClaim}
            onChange={handleChange('adminClaim')}
            placeholder="e.g. preferred_username"
            helperText="The claim to check for admin role"
            variant="outlined"
            size="small"
          />

          <TextField
            className={classes.field}
            label="Admin Value"
            value={config.adminValue}
            onChange={handleChange('adminValue')}
            placeholder="e.g. admin"
            helperText="The value that grants admin role"
            variant="outlined"
            size="small"
          />

          <TextField
            className={classes.field}
            label="Groups Claim"
            value={config.groupsClaim}
            onChange={handleChange('groupsClaim')}
            placeholder="groups"
            variant="outlined"
            size="small"
          />
        </div>
      </CardContent>
      <CardActions className={classes.actions}>
        <Button
          variant="contained"
          color="primary"
          onClick={handleSave}
          disabled={saving}
        >
          {saving && <CircularProgress size={20} style={{ marginRight: 8 }} />}
          Save
        </Button>
      </CardActions>
    </Card>
  )
}

export default OIDCSettings
