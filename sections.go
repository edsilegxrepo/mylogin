package mylogin

// Section represents one section of the plaintext content of mylogin.cnf.
type Section struct {
	Name  string `json:"name"`
	Login Login  `json:"login"`
}

// Sections represents the structured content of the plaintext of mylogin.cnf.
type Sections []Section

// Login returns the Login from the section with the given name.
func (sections Sections) Login(section string) *Login {
	for i := range sections {
		if sections[i].Name == section {
			return &sections[i].Login
		}
	}
	return nil
}

// Has reports whether a section with the given name exists.
func (sections Sections) Has(section string) bool {
	return sections.Login(section) != nil
}

// Names returns the names of all sections in order.
func (sections Sections) Names() []string {
	names := make([]string, len(sections))
	for i, s := range sections {
		names[i] = s.Name
	}
	return names
}

// Merge returns a single Login which is the result of the ordered merge
// of the sections with the given names (see Login.Merge).
// For each option, the last section that has a value takes precedence.
func (sections Sections) Merge(sectionNames []string) (login *Login) {
	for _, s := range sectionNames {
		if s == "" {
			s = DefaultSection
		}
		l := sections.Login(s)
		if l.IsEmpty() {
			continue
		}
		if login == nil {
			login = new(Login)
		}
		login.Merge(l)
	}

	return
}
