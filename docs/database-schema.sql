--
-- PostgreSQL database dump
--


-- Dumped from database version 17.11
-- Dumped by pg_dump version 17.11

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: affected_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.affected_packages (
    id bigint NOT NULL,
    vulnerability_id character varying(64) NOT NULL,
    ecosystem character varying(128) NOT NULL,
    distro character varying(32),
    release character varying(64),
    package_name character varying(256) NOT NULL,
    source_package character varying(256),
    ranges jsonb NOT NULL,
    status character varying(16) NOT NULL,
    fixed_version text,
    source character varying(32) NOT NULL,
    source_url text NOT NULL,
    entry_hash character varying(64) NOT NULL,
    advisory_id character varying(128),
    package_key character varying(16),
    requires_subscription boolean DEFAULT false NOT NULL,
    source_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT ck_affected_status CHECK (((status)::text = ANY ((ARRAY['fixed'::character varying, 'unfixed'::character varying, 'wont_fix'::character varying, 'unknown'::character varying])::text[])))
);


--
-- Name: affected_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.affected_packages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: affected_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.affected_packages_id_seq OWNED BY public.affected_packages.id;


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: epss_scores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.epss_scores (
    vulnerability_id character varying(64) NOT NULL,
    score_date date NOT NULL,
    epss numeric(10,9) NOT NULL,
    percentile numeric(10,9) NOT NULL,
    model_version character varying(64) NOT NULL,
    CONSTRAINT ck_epss_percentile CHECK (((percentile >= (0)::numeric) AND (percentile <= (1)::numeric))),
    CONSTRAINT ck_epss_probability CHECK (((epss >= (0)::numeric) AND (epss <= (1)::numeric)))
);


--
-- Name: ingestion_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingestion_state (
    source character varying(64) NOT NULL,
    source_revision text,
    cursor jsonb NOT NULL,
    records_processed bigint NOT NULL,
    completed boolean NOT NULL,
    last_success_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_error text,
    has_completed boolean DEFAULT false NOT NULL
);


--
-- Name: kev_entries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kev_entries (
    vulnerability_id character varying(64) NOT NULL,
    date_added date NOT NULL,
    due_date date,
    vendor text NOT NULL,
    product text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    required_action text NOT NULL,
    ransomware character varying(32) NOT NULL,
    notes text NOT NULL,
    catalog_version character varying(64) NOT NULL,
    record_hash character varying(64) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    removed_at timestamp with time zone
);


--
-- Name: osv_advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.osv_advisories (
    id character varying(128) NOT NULL,
    ecosystem character varying(32) NOT NULL,
    modified_at timestamp with time zone NOT NULL,
    withdrawn_at timestamp with time zone,
    record_hash character varying(64) NOT NULL,
    raw_record jsonb NOT NULL
);


--
-- Name: scheduled_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduled_tasks (
    name character varying(32) NOT NULL,
    next_run_at timestamp with time zone NOT NULL,
    last_finished_at timestamp with time zone
);


--
-- Name: task_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.task_runs (
    id bigint NOT NULL,
    task character varying(32) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    elapsed_seconds double precision,
    attempt integer NOT NULL,
    status character varying(16) NOT NULL,
    result jsonb NOT NULL,
    error character varying(256)
);


--
-- Name: task_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.task_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: task_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.task_runs_id_seq OWNED BY public.task_runs.id;


--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerabilities (
    id character varying(64) NOT NULL,
    status character varying(16) NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    published_at timestamp with time zone,
    modified_at timestamp with time zone,
    cvss double precision,
    severity character varying(16),
    cwes jsonb NOT NULL,
    ssvc jsonb,
    adp_kev_flag boolean DEFAULT false NOT NULL,
    cisa_adp jsonb,
    source_url text,
    record_hash character varying(64),
    raw_record jsonb,
    ingested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    cvss_version character varying(8),
    cvss_vector text,
    cvss_source character varying(32),
    cvss_metrics jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT ck_vulnerability_cvss CHECK (((cvss IS NULL) OR ((cvss >= (0)::double precision) AND (cvss <= (10)::double precision)))),
    CONSTRAINT ck_vulnerability_status CHECK (((status)::text = ANY ((ARRAY['PUBLISHED'::character varying, 'REJECTED'::character varying, 'RESERVED'::character varying, 'UNKNOWN'::character varying])::text[])))
);


--
-- Name: vulnerability_aliases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_aliases (
    vulnerability_id character varying(64) NOT NULL,
    alias character varying(128) NOT NULL,
    source character varying(32) NOT NULL
);


--
-- Name: vulnerability_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vulnerability_events (
    id bigint NOT NULL,
    vulnerability_id character varying(64) NOT NULL,
    event_type character varying(64) NOT NULL,
    dedup_key character varying(64) NOT NULL,
    source character varying(32) NOT NULL,
    happened_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    priority character varying(8) NOT NULL,
    payload jsonb NOT NULL,
    is_baseline boolean DEFAULT true NOT NULL
);


--
-- Name: vulnerability_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vulnerability_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulnerability_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vulnerability_events_id_seq OWNED BY public.vulnerability_events.id;


--
-- Name: affected_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_packages ALTER COLUMN id SET DEFAULT nextval('public.affected_packages_id_seq'::regclass);


--
-- Name: task_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.task_runs ALTER COLUMN id SET DEFAULT nextval('public.task_runs_id_seq'::regclass);


--
-- Name: vulnerability_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_events ALTER COLUMN id SET DEFAULT nextval('public.vulnerability_events_id_seq'::regclass);


--
-- Name: affected_packages affected_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_packages
    ADD CONSTRAINT affected_packages_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: epss_scores epss_scores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_scores
    ADD CONSTRAINT epss_scores_pkey PRIMARY KEY (vulnerability_id);


--
-- Name: ingestion_state ingestion_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingestion_state
    ADD CONSTRAINT ingestion_state_pkey PRIMARY KEY (source);


--
-- Name: kev_entries kev_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kev_entries
    ADD CONSTRAINT kev_entries_pkey PRIMARY KEY (vulnerability_id);


--
-- Name: osv_advisories osv_advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.osv_advisories
    ADD CONSTRAINT osv_advisories_pkey PRIMARY KEY (id);


--
-- Name: scheduled_tasks scheduled_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduled_tasks
    ADD CONSTRAINT scheduled_tasks_pkey PRIMARY KEY (name);


--
-- Name: task_runs task_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.task_runs
    ADD CONSTRAINT task_runs_pkey PRIMARY KEY (id);


--
-- Name: affected_packages uq_affected_source_entry; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_packages
    ADD CONSTRAINT uq_affected_source_entry UNIQUE (vulnerability_id, source, entry_hash);


--
-- Name: vulnerabilities vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_aliases vulnerability_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_aliases
    ADD CONSTRAINT vulnerability_aliases_pkey PRIMARY KEY (vulnerability_id, alias);


--
-- Name: vulnerability_events vulnerability_events_dedup_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_events
    ADD CONSTRAINT vulnerability_events_dedup_key_key UNIQUE (dedup_key);


--
-- Name: vulnerability_events vulnerability_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_events
    ADD CONSTRAINT vulnerability_events_pkey PRIMARY KEY (id);


--
-- Name: ix_affected_bundle; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_affected_bundle ON public.affected_packages USING btree (distro, release);


--
-- Name: ix_affected_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_affected_lookup ON public.affected_packages USING btree (ecosystem, package_name);


--
-- Name: ix_affected_packages_advisory_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_affected_packages_advisory_id ON public.affected_packages USING btree (advisory_id);


--
-- Name: ix_epss_scores_score_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_epss_scores_score_date ON public.epss_scores USING btree (score_date);


--
-- Name: ix_events_public_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_events_public_time ON public.vulnerability_events USING btree (is_baseline, happened_at);


--
-- Name: ix_events_time_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_events_time_priority ON public.vulnerability_events USING btree (happened_at, priority);


--
-- Name: ix_kev_entries_date_added; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_kev_entries_date_added ON public.kev_entries USING btree (date_added);


--
-- Name: ix_osv_advisories_ecosystem; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_osv_advisories_ecosystem ON public.osv_advisories USING btree (ecosystem);


--
-- Name: ix_task_runs_task; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_task_runs_task ON public.task_runs USING btree (task);


--
-- Name: ix_vulnerabilities_status_modified; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerabilities_status_modified ON public.vulnerabilities USING btree (status, modified_at);


--
-- Name: ix_vulnerability_aliases_alias; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_aliases_alias ON public.vulnerability_aliases USING btree (alias);


--
-- Name: ix_vulnerability_events_vulnerability_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vulnerability_events_vulnerability_id ON public.vulnerability_events USING btree (vulnerability_id);


--
-- Name: affected_packages affected_packages_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_packages
    ADD CONSTRAINT affected_packages_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE;


--
-- Name: epss_scores epss_scores_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_scores
    ADD CONSTRAINT epss_scores_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE;


--
-- Name: affected_packages fk_affected_advisory; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affected_packages
    ADD CONSTRAINT fk_affected_advisory FOREIGN KEY (advisory_id) REFERENCES public.osv_advisories(id);


--
-- Name: kev_entries kev_entries_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kev_entries
    ADD CONSTRAINT kev_entries_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE;


--
-- Name: vulnerability_aliases vulnerability_aliases_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_aliases
    ADD CONSTRAINT vulnerability_aliases_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE;


--
-- Name: vulnerability_events vulnerability_events_vulnerability_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vulnerability_events
    ADD CONSTRAINT vulnerability_events_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES public.vulnerabilities(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--


