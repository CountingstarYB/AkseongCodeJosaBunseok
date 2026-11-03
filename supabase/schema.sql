-- 악성코드 조사분석 보고서 에이전트 · Supabase 스키마
-- Supabase 대시보드 → SQL Editor에 통째로 붙여 넣고 Run. 여러 번 실행해도 안전합니다.
--
-- 원칙
--   1. 로그인한 사용자(authenticated)만 접근. 비로그인(anon)은 아무것도 못 함.
--   2. 각 사용자는 자기가 만든 사례만 읽기·쓰기·삭제 (owner_id = auth.uid()).
--   3. 사례 본문은 앱의 사례 객체를 그대로 data(jsonb)에 저장하고,
--      목록·검색에 쓰는 값만 별도 열로 둡니다.
--   ※ 공개 시연용입니다. 실제 부대·인원·장비 정보는 넣지 마세요.

-- ─────────────────────────────────────────────
-- 1. 테이블
-- ─────────────────────────────────────────────
create table if not exists public.cases (
  owner_id      uuid        not null default auth.uid()
                            references auth.users (id) on delete cascade,
  id            text        not null,                 -- 앱의 사례 id (uuid 또는 'example-pup' 등)
  title         text        not null default '',
  case_no       text        not null default '',
  analysis_date text        not null default '',      -- 앱 입력값 그대로 (YYYY-MM-DD)
  verdict       text        not null default '',
  sha256        text        not null default '',
  md5           text        not null default '',
  data          jsonb       not null,                 -- 사례 전체 (behaviors, iocs, timeline 등)
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  primary key (owner_id, id),
  constraint cases_id_len      check (char_length(id) between 1 and 100),
  constraint cases_data_object check (jsonb_typeof(data) = 'object'),
  constraint cases_data_size   check (pg_column_size(data) < 1000000)  -- 1MB 미만
);

comment on table public.cases is '악성코드 조사분석 사례 (사용자별 소유)';

create index if not exists cases_owner_date_idx on public.cases (owner_id, analysis_date desc);
create index if not exists cases_owner_sha256_idx on public.cases (owner_id, sha256) where sha256 <> '';
create index if not exists cases_owner_md5_idx on public.cases (owner_id, md5) where md5 <> '';

-- ─────────────────────────────────────────────
-- 2. updated_at 자동 갱신
-- ─────────────────────────────────────────────
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists cases_set_updated_at on public.cases;
create trigger cases_set_updated_at
  before update on public.cases
  for each row execute function public.set_updated_at();

-- ─────────────────────────────────────────────
-- 3. GRANT — 테이블 권한
--    anon(비로그인)·public은 전부 회수, authenticated에만 CRUD 허용.
--    실제 어떤 행에 접근할지는 아래 RLS가 결정합니다.
-- ─────────────────────────────────────────────
revoke all on table public.cases from public, anon;
grant select, insert, update, delete on table public.cases to authenticated;

revoke all on function public.set_updated_at() from public, anon, authenticated;

-- ─────────────────────────────────────────────
-- 4. RLS — 행 단위 보안
-- ─────────────────────────────────────────────
alter table public.cases enable row level security;

drop policy if exists "cases_select_own" on public.cases;
drop policy if exists "cases_insert_own" on public.cases;
drop policy if exists "cases_update_own" on public.cases;
drop policy if exists "cases_delete_own" on public.cases;

create policy "cases_select_own" on public.cases
  for select to authenticated
  using ((select auth.uid()) = owner_id);

create policy "cases_insert_own" on public.cases
  for insert to authenticated
  with check ((select auth.uid()) = owner_id);

create policy "cases_update_own" on public.cases
  for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);      -- 다른 사람 소유로 바꾸기 금지

create policy "cases_delete_own" on public.cases
  for delete to authenticated
  using ((select auth.uid()) = owner_id);

-- ─────────────────────────────────────────────
-- 5. 확인용 (선택) — relrowsecurity = true, 정책 4개, 권한은 authenticated만 나오면 정상
-- ─────────────────────────────────────────────
-- select relname, relrowsecurity from pg_class where relname = 'cases';
-- select policyname, cmd, roles from pg_policies where tablename = 'cases';
-- select grantee, privilege_type from information_schema.role_table_grants where table_name = 'cases';
