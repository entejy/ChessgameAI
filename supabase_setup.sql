-- Uruchom w Supabase SQL Editor. Wymagane: Supabase Auth Email/Password.
create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 nickname text not null default 'Gracz' check (char_length(nickname) between 2 and 24),
 bio text not null default '' check (char_length(bio) <= 180),
 avatar_path text,
 updated_at timestamptz not null default now(),
 constraint avatar_own_path check (avatar_path is null or avatar_path like id::text || '/%')
);
alter table public.profiles enable row level security;
drop policy if exists "Owner can read profile" on public.profiles;
drop policy if exists "Owner can insert profile" on public.profiles;
drop policy if exists "Owner can update profile" on public.profiles;
create policy "Owner can read profile" on public.profiles for select to authenticated using (auth.uid() = id);
create policy "Owner can insert profile" on public.profiles for insert to authenticated with check (auth.uid() = id);
create policy "Owner can update profile" on public.profiles for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('avatars','avatars',false,2097152,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=false,file_size_limit=2097152,allowed_mime_types=array['image/jpeg','image/png','image/webp'];
drop policy if exists "Owner reads avatar" on storage.objects;
drop policy if exists "Owner uploads avatar" on storage.objects;
drop policy if exists "Owner updates avatar" on storage.objects;
drop policy if exists "Owner deletes avatar" on storage.objects;
create policy "Owner reads avatar" on storage.objects for select to authenticated using (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "Owner uploads avatar" on storage.objects for insert to authenticated with check (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "Owner updates avatar" on storage.objects for update to authenticated using (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text) with check (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
create policy "Owner deletes avatar" on storage.objects for delete to authenticated using (bucket_id='avatars' and (storage.foldername(name))[1]=auth.uid()::text);
