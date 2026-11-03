-- ViroChess 2.6: uruchom RAZ w SQL Editor Supabase po supabase_setup.sql.
-- Właściciel to WYŁĄCZNIE zweryfikowany użytkownik Auth o wskazanym adresie.
alter table public.profiles add column if not exists country text;
alter table public.profiles add constraint viro_country_valid check (country is null or country in ('PL','DE','GB','US','UA','CZ','SK','FR','ES','IT','OTHER'));
create table if not exists public.viro_roles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 role text not null check(role in ('trusted','moderator')),
 updated_at timestamptz not null default now()
);
alter table public.viro_roles enable row level security;
revoke all on public.viro_roles from anon,authenticated;
-- Chronimy dane profilowe przed odczytem innych danych niż publiczny nick i kraj.
-- Istniejące polityki profilu pozostają bez zmian; funkcje zwracają tylko bezpieczne kolumny.
revoke update on public.profiles from authenticated;
grant update (nickname,bio,avatar_path,updated_at,country) on public.profiles to authenticated;
grant insert (id,nickname,bio,avatar_path,updated_at,country) on public.profiles to authenticated;
create or replace function public.viro_is_owner()
returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from auth.users u where u.id=auth.uid() and lower(u.email)='michalvitoxd@gmail.com' and u.email_confirmed_at is not null);
$$;
revoke all on function public.viro_is_owner() from public;
grant execute on function public.viro_is_owner() to authenticated;
create or replace function public.viro_my_role()
returns text language plpgsql stable security definer set search_path = '' as $$
declare result text;
begin
 if auth.uid() is null then return 'player'; end if;
 if public.viro_is_owner() then return 'owner'; end if;
 select role into result from public.viro_roles where user_id=auth.uid();
 return coalesce(result,'player');
end; $$;
revoke all on function public.viro_my_role() from public;
grant execute on function public.viro_my_role() to authenticated;
create or replace function public.viro_list_players()
returns table(id uuid,nickname text,country text,role text)
language sql stable security definer set search_path = '' as $$
 select p.id,p.nickname,p.country,
 case when lower(u.email)='michalvitoxd@gmail.com' and u.email_confirmed_at is not null then 'owner' else coalesce(r.role,'player') end as role
 from public.profiles p join auth.users u on u.id=p.id
 left join public.viro_roles r on r.user_id=p.id
 where auth.uid() is not null and char_length(p.nickname)>=2
 order by p.updated_at desc limit 100;
$$;
revoke all on function public.viro_list_players() from public;
grant execute on function public.viro_list_players() to authenticated;
create or replace function public.viro_admin_players()
returns table(id uuid,nickname text,country text,role text)
language plpgsql stable security definer set search_path = '' as $$
begin
 if not public.viro_is_owner() then raise exception 'Brak uprawnień'; end if;
 return query select * from public.viro_list_players();
end; $$;
revoke all on function public.viro_admin_players() from public;
grant execute on function public.viro_admin_players() to authenticated;
create or replace function public.viro_set_role(target_user uuid,new_role text)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if not public.viro_is_owner() then raise exception 'Brak uprawnień'; end if;
 if new_role not in ('player','trusted','moderator') then raise exception 'Nieprawidłowa rola'; end if;
 if not exists(select 1 from auth.users where id=target_user) then raise exception 'Użytkownik nie istnieje'; end if;
 if exists(select 1 from auth.users where id=target_user and lower(email)='michalvitoxd@gmail.com' and email_confirmed_at is not null) then raise exception 'Nie można zmienić roli właściciela'; end if;
 if new_role='player' then delete from public.viro_roles where user_id=target_user;
 else insert into public.viro_roles(user_id,role) values(target_user,new_role)
 on conflict(user_id) do update set role=excluded.role,updated_at=now(); end if;
end; $$;
revoke all on function public.viro_set_role(uuid,text) from public;
grant execute on function public.viro_set_role(uuid,text) to authenticated;
