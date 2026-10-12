-- MT-S7 · reset de senha entre sócios. Rode uma vez: Supabase → SQL Editor → New query → Run.

-- 1) Sócios enxergam a lista de sócios (para escolher de quem resetar)
drop policy if exists "socios veem membros" on public.mts7_membros;
create policy "socios veem membros" on public.mts7_membros
  for select using (public.mts7_is_member());

-- 2) Um sócio define uma senha provisória para outro sócio (só e-mails da tabela mts7_membros)
create or replace function public.mts7_reset_socio(alvo text, nova text)
returns text language plpgsql security definer
set search_path = public, extensions, auth as $$
begin
  if not public.mts7_is_member() then raise exception 'Sem permissão'; end if;
  if not exists (select 1 from public.mts7_membros where lower(email) = lower(alvo)) then
    raise exception 'Esse e-mail não é sócio do MT-S7'; end if;
  if length(coalesce(nova,'')) < 6 then raise exception 'Senha precisa ter 6+ caracteres'; end if;
  update auth.users
     set encrypted_password = extensions.crypt(nova, extensions.gen_salt('bf')),
         email_confirmed_at = coalesce(email_confirmed_at, now()),
         updated_at = now()
   where lower(email) = lower(alvo);
  if not found then return 'sem_conta'; end if;
  return 'ok';
end $$;
revoke all on function public.mts7_reset_socio(text, text) from public, anon;
grant execute on function public.mts7_reset_socio(text, text) to authenticated;
