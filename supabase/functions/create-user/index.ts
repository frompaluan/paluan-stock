import { serve } from 'https://deno.land/std@0.177.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { corsHeaders } from '../_shared/cors.ts'

// Cargos aceitos. Qualquer outro valor enviado pelo front-end é recusado.
const ALLOWED_ROLES = ['user', 'admin']

function jsonResponse(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    status,
  })
}

serve(async (req) => {
  // Tratamento para requisição OPTIONS (necessário para CORS)
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'Método não permitido.' }, 405)
  }

  try {
    // 1. Exige o token de quem está chamando.
    //    A anon key sozinha não basta: precisa ser a sessão de um usuário logado.
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
      return jsonResponse({ error: 'Autorização necessária.' }, 401)
    }

    // 2. Cliente com as permissões de quem chamou (não as de administrador),
    //    usado só para descobrir quem é e qual o cargo.
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } }
    )

    const { data: userData, error: userError } = await supabaseClient.auth.getUser()
    if (userError || !userData?.user) {
      return jsonResponse({ error: 'Usuário não autenticado.' }, 401)
    }

    // 3. Só administradores ativos podem criar usuários.
    const { data: callerProfile, error: callerError } = await supabaseClient
      .from('profiles')
      .select('role, status')
      .eq('id', userData.user.id)
      .single()

    if (callerError || callerProfile?.role !== 'admin' || callerProfile?.status === 'blocked') {
      return jsonResponse({ error: 'Acesso negado: apenas administradores podem criar usuários.' }, 403)
    }

    // 4. Valida os dados do novo usuário.
    const { email, password, fullName, role } = await req.json()

    if (!email || !password || !fullName || !role) {
      return jsonResponse({ error: 'Campos obrigatórios ausentes.' }, 400)
    }
    if (!ALLOWED_ROLES.includes(role)) {
      return jsonResponse({ error: 'Cargo inválido.' }, 400)
    }
    if (typeof password !== 'string' || password.length < 8) {
      return jsonResponse({ error: 'A senha precisa ter pelo menos 8 caracteres.' }, 400)
    }

    // 5. Só agora usa a chave de administrador (service role).
    const supabaseAdmin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
    )

    const { data: authData, error: authError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true, // O usuário é criado como confirmado
      user_metadata: { full_name: fullName, role },
    })

    if (authError || !authData?.user) {
      console.error('Erro ao criar usuário na autenticação:', authError?.message)
      return jsonResponse({ error: authError?.message ?? 'Não foi possível criar o usuário.' }, 400)
    }

    // 6. Grava nome e cargo no perfil. Se falhar, desfaz a criação
    //    para não deixar um usuário sem perfil.
    const { error: profileError } = await supabaseAdmin
      .from('profiles')
      .update({ full_name: fullName, role })
      .eq('id', authData.user.id)

    if (profileError) {
      console.error('Falha ao atualizar perfil; desfazendo criação do usuário:', profileError.message)
      await supabaseAdmin.auth.admin.deleteUser(authData.user.id)
      return jsonResponse({ error: 'Não foi possível salvar o perfil do usuário.' }, 500)
    }

    return jsonResponse({ message: 'Usuário criado com sucesso!' }, 200)
  } catch (error) {
    console.error('Erro inesperado em create-user:', error?.message)
    return jsonResponse({ error: 'Erro ao processar a requisição.' }, 400)
  }
})
