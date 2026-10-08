import { createClient } from 'npm:@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  if (req.method !== 'POST') return json({ error: 'Método no permitido.' }, 405)

  const authHeader = req.headers.get('Authorization')
  if (!authHeader?.startsWith('Bearer ')) return json({ error: 'No autenticado.' }, 401)

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const secretKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || Deno.env.get('SUPABASE_SECRET_KEY')
  if (!secretKey) return json({ error: 'Falta configurar la clave secreta del servidor.' }, 500)

  const admin = createClient(supabaseUrl, secretKey, { auth: { autoRefreshToken: false, persistSession: false } })
  const token = authHeader.replace('Bearer ', '')
  const { data: { user: caller }, error: callerError } = await admin.auth.getUser(token)
  if (callerError || !caller) return json({ error: 'Sesión no válida.' }, 401)

  const { data: callerProfile, error: profileError } = await admin
    .from('usuarios')
    .select('id, rol, activo')
    .eq('id', caller.id)
    .maybeSingle()

  if (profileError || !callerProfile || callerProfile.rol !== 'administrador' || callerProfile.activo !== true) {
    return json({ error: 'No tienes permisos de administrador.' }, 403)
  }

  let payload: { nombre?: string; apellido?: string; email?: string; rol?: string; enviarInvitacion?: boolean }
  try { payload = await req.json() } catch { return json({ error: 'Datos inválidos.' }, 400) }

  const nombre = (payload.nombre || '').trim()
  const apellido = (payload.apellido || '').trim()
  const email = (payload.email || '').trim().toLowerCase()
  const rol = payload.rol || 'estudiante'
  const enviarInvitacion = payload.enviarInvitacion !== false

  if (!nombre || !apellido || !email) return json({ error: 'Nombre, apellido y correo son obligatorios.' }, 400)
  if (!['estudiante', 'tutor', 'administrador'].includes(rol)) return json({ error: 'Rol no válido.' }, 400)

  // Invitar por correo evita guardar contraseñas temporales en el panel.
  // El usuario completa su acceso desde el correo de Supabase.
  const metadata = { nombre, apellido, rol }
  let result
  if (enviarInvitacion) {
    result = await admin.auth.admin.inviteUserByEmail(email, { data: metadata })
  } else {
    return json({ error: 'Por seguridad, esta versión requiere invitación por correo.' }, 400)
  }

  if (result.error || !result.data.user) {
    return json({ error: result.error?.message || 'No se pudo crear el usuario.' }, 400)
  }

  // El trigger existente crea el perfil. El upsert garantiza que el perfil
  // quede sincronizado incluso si el trigger todavía no estuviera activo.
  const { error: upsertError } = await admin.from('usuarios').upsert({
    id: result.data.user.id,
    nombre,
    apellido,
    email,
    rol,
    activo: true,
  }, { onConflict: 'id' })

  if (upsertError) {
    await admin.auth.admin.deleteUser(result.data.user.id)
    return json({ error: 'El usuario Auth se creó, pero no se pudo crear su perfil. La operación fue revertida.' }, 500)
  }

  return json({ ok: true, userId: result.data.user.id, email, rol, invitationSent: true })
})
