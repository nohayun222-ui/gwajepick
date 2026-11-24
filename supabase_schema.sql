-- 과제픽 Supabase schema starter
-- Apply in Supabase SQL Editor. Review policies before production use.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'student' check (role in ('student','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.submissions (
  id uuid primary key default gen_random_uuid(),
  submitted_by uuid references auth.users(id) on delete set null,
  image_url text not null,
  title text not null,
  source_site text not null,
  source_page_url text not null,
  creator text,
  license_name text,
  license_url text,
  commercial_use text not null default 'unknown',
  attribution_required text not null default 'unknown',
  topics text[] not null default '{}',
  review_status text not null default 'pending' check (review_status in ('pending','verified','rejected','hidden')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id)
);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  submission_id uuid references public.submissions(id) on delete cascade,
  commons_page_url text,
  reason text not null,
  details text,
  reporter_id uuid references auth.users(id) on delete set null,
  status text not null default 'open' check (status in ('open','reviewing','resolved','dismissed')),
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by uuid references auth.users(id)
);

alter table public.profiles enable row level security;
alter table public.submissions enable row level security;
alter table public.reports enable row level security;

-- Admin status is stored in profiles and must be granted manually by a trusted project owner.
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin') $$;

create policy "profiles self read" on public.profiles for select to authenticated using (id = auth.uid() or public.is_admin());
create policy "public can read approved submissions" on public.submissions for select using (review_status = 'verified' or public.is_admin());
create policy "authenticated can submit pending" on public.submissions for insert to authenticated
with check (submitted_by = auth.uid() and review_status = 'pending');
create policy "admins manage submissions" on public.submissions for all to authenticated
using (public.is_admin()) with check (public.is_admin());

create policy "authenticated can report" on public.reports for insert to authenticated
with check (reporter_id = auth.uid() and status = 'open');
create policy "admins read and manage reports" on public.reports for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Create a profile row on signup. Role is always student; never trust user metadata for admin.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$ begin
  insert into public.profiles(id, role) values (new.id, 'student') on conflict (id) do nothing;
  return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

-- To promote an administrator, run manually as database owner:
-- update public.profiles set role = 'admin' where id = 'AUTH_USER_UUID';
