'use strict';
const set = (s) => new Set(s.split(/\s+/).filter(Boolean));

// Common given names (lower-case). A capitalised word from this list followed by a capitalised
// surname is treated as a person. Extend freely (or swap for Presidio's NER - see README).
const FIRST_NAMES = set(`james john robert michael william david richard joseph thomas charles christopher daniel
matthew anthony mark donald steven paul andrew joshua kenneth kevin brian george timothy ronald edward jason jeffrey
ryan jacob gary nicholas eric jonathan stephen larry justin scott brandon benjamin samuel gregory alexander patrick
frank raymond jack dennis jerry tyler aaron jose adam nathan henry douglas zachary peter kyle walter ethan jeremy
harold keith christian roger noah gerald carl terry sean austin arthur lawrence jesse dylan bryan joe jordan billy
bruce albert gabriel logan alan juan wayne roy ralph randy eugene vincent russell elijah louis bobby philip johnny
mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa nancy betty margaret sandra ashley
kimberly emily donna michelle carol amanda dorothy melissa deborah stephanie rebecca sharon laura cynthia kathleen
amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra rachel carolyn janet
catherine maria heather diane ruth julie olivia joyce victoria kelly lauren christina joan evelyn judith megan
andrea cheryl hannah jacqueline martha gloria teresa ann sara madison frances kathryn janice jean abigail alice
judy sophia denise amber doris marilyn danielle beverly isabella theresa diana natalie brittany charlotte marie
kayla alexis lori jane priya rahul amit raj anil sunil vikram neha pooja rohan arjun ravi anjali sanjay deepak
wei li chen yuki hiroshi carlos miguel luis jorge sofia lucia elena ahmed mohammed omar fatima aisha ivan olga`);

// Capitalised tokens that are never part of a person name (document vocabulary, orgs, calendar...).
const DENY = set(`investment investments agreement agreements client clients firm securities exchange commission fund
funds capital wealth partners partner index rule rules section account accounts number date email phone address
street avenue road boulevard lane drive court way place terrace parkway highway circle square trail plaza management
advisory advisors advisor financial services group bank trust corporation company association authority federal
reserve national inc llc llp ltd corp the and of for to in on at by with this that these those all any each our your
their its dear sir madam january february march april may june july august september october november december monday
tuesday wednesday thursday friday saturday sunday finra sec fdic annual quarterly monthly return returns risk
disclosure disclosures disclaimer important notice terms conditions privacy policy statement report review
compliance legal fee fees portfolio balance deposit contract brochure newsletter team department division office
north south east west united states america american market markets stock stocks bond bonds dow jones nasdaq
standard poor poors guarantee guaranteed we you he she it they i a an is are was were be will shall can not no yes
presentation overview summary profile questionnaire form application update letter period plan plans
industrial average rate rates inflation treasury everyone hello hi`);

// Well-known organisations that look like "First Last" - suppressed.
const ORG_ALLOW = new Set(['charles schwab', 'john hancock', 'wells fargo', 'morgan stanley', 'goldman sachs',
  'merrill lynch', 'jp morgan', 'franklin templeton', 'raymond james', 'edward jones']);

module.exports = { FIRST_NAMES, DENY, ORG_ALLOW };
