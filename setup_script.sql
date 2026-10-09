-- ==========================================
-- 1. สร้างตารางพื้นฐาน
-- ==========================================
CREATE TABLE teachers (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE
);

CREATE TABLE students (
    id VARCHAR(5) PRIMARY KEY, -- รหัสนักเรียน 5 หลัก
    title VARCHAR(20),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    section VARCHAR(10),
    user_id UUID UNIQUE REFERENCES auth.users(id) ON DELETE SET NULL,
    photo_path TEXT
);

CREATE TABLE attempts (
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    kind VARCHAR(4) CHECK (kind IN ('pre', 'post')),
    score INTEGER NOT NULL,
    answers JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, kind)
);

CREATE TABLE progress (
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    done BOOLEAN DEFAULT FALSE,
    PRIMARY KEY (user_id, unit)
);

CREATE TABLE submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    unit INTEGER NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('link', 'file')),
    url TEXT,
    storage_path TEXT,
    note TEXT,
    score INTEGER,
    teacher_comment TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE materials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    kind VARCHAR(10) CHECK (kind IN ('file', 'link', 'video')),
    url TEXT,
    storage_path TEXT,
    file_name TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ==========================================
-- 2. ฟังก์ชันตรวจสอบสิทธิ์ผู้สอน
-- ==========================================
CREATE OR REPLACE FUNCTION public.is_teacher()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN EXISTS (SELECT 1 FROM teachers WHERE user_id = auth.uid());
END;
$$;

-- ==========================================
-- 3. Row Level Security (RLS) Policies
-- ==========================================
ALTER TABLE teachers ENABLE ROW LEVEL SECURITY;
ALTER TABLE students ENABLE ROW LEVEL SECURITY;
ALTER TABLE attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE materials ENABLE ROW LEVEL SECURITY;

-- Revoke anon
REVOKE ALL ON teachers, students, attempts, progress, submissions, materials FROM anon;

-- Teachers Policy
CREATE POLICY "Teachers can view all teachers" ON teachers FOR SELECT TO authenticated USING (true);

-- Students Policy
CREATE POLICY "Students view own, Teacher views all" ON students FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());

CREATE POLICY "Students can update own photo" ON students FOR UPDATE TO authenticated 
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());

-- Attempts Policy
CREATE POLICY "Users insert own attempt" ON attempts FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Users view own, Teacher views all" ON attempts FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());

-- Progress Policy
CREATE POLICY "Users insert/update own progress" ON progress FOR ALL TO authenticated 
USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY "Teacher views all progress" ON progress FOR SELECT TO authenticated USING (is_teacher());

-- Submissions Policy
CREATE POLICY "Users insert own submission" ON submissions FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid());
CREATE POLICY "Users update own submission" ON submissions FOR UPDATE TO authenticated USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());
CREATE POLICY "Users view own, Teacher views all submissions" ON submissions FOR SELECT TO authenticated 
USING (user_id = auth.uid() OR is_teacher());
CREATE POLICY "Teacher updates all submissions" ON submissions FOR UPDATE TO authenticated USING (is_teacher());

-- Materials Policy
CREATE POLICY "All authenticated can view materials" ON materials FOR SELECT TO authenticated USING (true);
CREATE POLICY "Only teachers can modify materials" ON materials FOR ALL TO authenticated USING (is_teacher()) WITH CHECK (is_teacher());

-- ==========================================
-- 4. Triggers ป้องกันนักเรียนแก้ไขคะแนนตัวเอง และ ผูกบัญชี
-- ==========================================
CREATE OR REPLACE FUNCTION protect_submission_updates()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF NOT is_teacher() THEN
        NEW.score = OLD.score;
        NEW.teacher_comment = OLD.teacher_comment;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_protect_submission BEFORE UPDATE ON submissions
FOR EACH ROW EXECUTE FUNCTION protect_submission_updates();

-- Trigger ผูกบัญชีนักเรียน (เช็ค 5 หลัก)
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    extracted_id VARCHAR(5);
BEGIN
    -- ดึง 5 ตัวแรกจากอีเมล (สมมติอีเมลรูปแบบ 12345@nws.ac.th)
    extracted_id := SUBSTRING(NEW.email FROM '^([0-9]{5})@');
    
    IF extracted_id IS NOT NULL THEN
        -- ถ้านักเรียนมีรหัสในระบบและยังไม่ผูก user_id
        IF EXISTS (SELECT 1 FROM students WHERE id = extracted_id AND user_id IS NULL) THEN
            UPDATE students SET user_id = NEW.id WHERE id = extracted_id;
        ELSE
            RAISE EXCEPTION 'รหัสนักเรียนไม่มีในระบบ หรือถูกลงทะเบียนไปแล้ว';
        END IF;
    ELSE
        -- ถ้าไม่ใช่ 5 หลัก ให้ถือว่าเป็นอาจารย์
        INSERT INTO teachers (user_id) VALUES (NEW.id);
    END IF;
    
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users
FOR EACH ROW EXECUTE FUNCTION handle_new_user();

-- ==========================================
-- 5. View สำหรับอาจารย์ (Security Invoker)
-- ==========================================
CREATE VIEW student_results WITH (security_invoker = true) AS
SELECT 
    s.id, s.title, s.first_name, s.last_name, s.section, s.photo_path,
    pre.score AS pre_score, post.score AS post_score,
    (SELECT COUNT(*) FROM progress WHERE user_id = s.user_id AND done = true) AS units_completed
FROM students s
LEFT JOIN attempts pre ON s.user_id = pre.user_id AND pre.kind = 'pre'
LEFT JOIN attempts post ON s.user_id = post.user_id AND post.kind = 'post'
WHERE s.user_id IS NOT NULL;

-- ==========================================
-- 6. Storage Setup
-- ==========================================
-- สร้าง Buckets (ต้องรันด้วย superuser หรือผ่าน UI ปกติ, หากรันไม่ได้ให้สร้างผ่าน UI)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES 
  ('photos', 'photos', false, 2097152, ARRAY['image/jpeg', 'image/png']),
  ('submissions', 'submissions', false, 20971520, ARRAY['image/jpeg', 'image/png', 'application/pdf', 'video/mp4']),
  ('materials', 'materials', false, 52428800, ARRAY['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'])
ON CONFLICT (id) DO NOTHING;

-- Policies for photos
CREATE POLICY "User controls own photo folder" ON storage.objects FOR ALL TO authenticated 
USING (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text) 
WITH CHECK (bucket_id = 'photos' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teachers can read all photos" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'photos' AND is_teacher());

-- Policies for submissions
CREATE POLICY "User controls own submission folder" ON storage.objects FOR ALL TO authenticated 
USING (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text) 
WITH CHECK (bucket_id = 'submissions' AND (storage.foldername(name))[1] = auth.uid()::text);
CREATE POLICY "Teachers can read all submissions" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'submissions' AND is_teacher());

-- Policies for materials
CREATE POLICY "All auth can read materials" ON storage.objects FOR SELECT TO authenticated USING (bucket_id = 'materials');
CREATE POLICY "Teachers can manage materials" ON storage.objects FOR ALL TO authenticated USING (bucket_id = 'materials' AND is_teacher()) WITH CHECK (bucket_id = 'materials' AND is_teacher());

-- ==========================================
-- 7. ข้อมูลจำลอง 6 แถว (วิธีเพิ่มข้อมูลจริง: นำเข้า CSV ใส่ตาราง students ผ่าน Table Editor โดยเว้น user_id ว่างไว้)
-- ==========================================
INSERT INTO students (id, title, first_name, last_name, section) VALUES
('10001', 'นาย', 'สมชาย', 'ใจดี', 'ม.5/1'),
('10002', 'นางสาว', 'สมหญิง', 'รักเรียน', 'ม.5/1'),
('10003', 'นาย', 'สมศักดิ์', 'หมั่นเพียร', 'ม.5/1'),
('10004', 'นางสาว', 'สมศรี', 'มีโชค', 'ม.5/2'),
('10005', 'นาย', 'สมบูรณ์', 'พูนสุข', 'ม.5/2'),
('10006', 'นางสาว', 'สมทรง', 'คงกระพัน', 'ม.5/2');

-- หมายเหตุ: หากต้องการตั้งผู้สอนแบบ Manual ให้หา UUID ของ Auth User แล้วมารันคำสั่งนี้
-- INSERT INTO teachers (user_id) VALUES ('uuid-ของ-อาจารย์-จาก-auth.users');