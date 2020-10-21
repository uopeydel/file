using System;
using System.Text;
using System.Threading.Tasks;
using mf_service.LDAP.Contract;
using mf_service.LDAP.Repository.Interface;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Utilclass;

namespace mf_service.LDAP.Repository.Implement
{
    public class LDAPRepository : ILDAPRepository
    {
        private const string mSAMAccountNameKey = "sAMAccountName";
        private const string mDisplayNameKey = "displayname";
        private const string mDisplayThaiNameKey = "msDS-PhoneticDisplayName";
        private const string mRoleEnKey = "extensionAttribute5";
        private const string mBranchThKey = "extensionAttribute6";
        private const string mRoleThKey = "extensionAttribute1";
        private const string mSexKey = "extensionAttribute14";
        private const string mMemberOfKey = "memberOf";

        public Tuple<LDAPLoginResponseContract, string> Requester(
            string host,
            string baseConnector,
            string usernameSuffix,
            string userName,
            string password)
        {
            var result = new LDAPLoginResponseContract();
            string memberOf = string.Empty;
            var searchAttr = new string[]
            {
                mSAMAccountNameKey,
                mDisplayNameKey,
                mDisplayThaiNameKey,
                mRoleEnKey,
                mBranchThKey,
                mRoleThKey,
                mSexKey,
                mMemberOfKey,
            };
            try
            {
                using (var connection = new LdapConnection {SecureSocketLayer = false})
                {
                    connection.Connect(host, LdapConnection.DEFAULT_PORT);
                    connection.Bind(userName + usernameSuffix, password);

                    if (connection.Bound)
                    {
                        var lsc = connection.Search(
                            baseConnector,
                            LdapConnection.SCOPE_SUB,
                            $"(&(objectClass=person)(sAMAccountName={userName}))",
                            searchAttr,
                            false
                        );
                        while (lsc.hasMore())
                        {
                            LdapEntry nextEntry = null;
                            try
                            {
                                nextEntry = lsc.next();
                            }
                            catch
                            {
                                continue;
                            }

                            LdapAttributeSet attributeSet = nextEntry.getAttributeSet();
                            System.Collections.IEnumerator ienum = attributeSet.GetEnumerator();
                            while (ienum.MoveNext())
                            {
                                LdapAttribute attribute = (LdapAttribute) ienum.Current;
                                string attributeName = attribute.Name;
                                string attributeVal = attribute.StringValue;
                                switch (attributeName)
                                {
                                    case mSAMAccountNameKey:
                                    {
                                        result.userId = attributeVal.Substring(attributeVal.IndexOf(':') + 1).Trim();
                                        break;
                                    }
                                    case mDisplayNameKey:
                                    {
                                        result.fullName = attributeVal.Substring(attributeVal.IndexOf(':') + 1).Trim();
                                        break;
                                    }
                                    case mDisplayThaiNameKey:
                                    {
                                        result.fullNameTh =
                                            attributeVal.Substring(attributeVal.IndexOf(':') + 1).Trim();
                                        break;
                                    }
                                    case mRoleEnKey:
                                    {
                                        string[] roleEnList = attributeVal.Split('|');
                                        string roleEn = roleEnList[0].Substring(roleEnList[0].IndexOf(':') + 1).Trim();
                                        result.roleEn = roleEn;
                                        break;
                                    }
                                    case mBranchThKey:
                                    {
                                        string[] branch = attributeVal.Split('|');
                                        result.branchTh = branch[0].Trim();
                                        result.branchCode = branch[1].Trim();
                                        break;
                                    }
                                    case mRoleThKey:
                                    {
                                        string[] role = attributeVal.Split('|');
                                        result.roleTh = role[0].Trim();
                                        result.roleCode = role[1].Trim();
                                        break;
                                    }
                                    case mSexKey:
                                    {
                                        result.sex = attributeVal.Substring(attributeVal.IndexOf(':') + 1).Trim();
                                        break;
                                    }
                                    case mMemberOfKey:
                                    {
                                        result.channel = ""; //TODO implement role
                                        memberOf += (" MEMBEROF " + string.Join(" , ", attribute.StringValueArray));
                                        result.authority = ConfigRoleByMemberOf(attribute.StringValueArray);
                                        break;
                                    }
                                    default:
                                        break;
                                }
                            }
                        }

                        connection.Disconnect();
                    }
                }

                if (string.IsNullOrEmpty(result.authority))
                {
                    return new Tuple<LDAPLoginResponseContract, string>(null, memberOf);
                }

                return new Tuple<LDAPLoginResponseContract, string>(result, memberOf);
            }
            catch (Exception e)
            {
                return new Tuple<LDAPLoginResponseContract, string>(null, memberOf + " " + e.ToString());
            }
        }

        private string ConfigRoleByMemberOf(string[] memberOfs)
        {
            foreach (var memberOfString in memberOfs)
            {
                var memberOfValue = memberOfString.Substring(memberOfString.IndexOf(':') + 1).Trim();
                string[] typeList = memberOfValue.Split(',');
                if (!memberOfValue.Contains("Mutual Fund API"))
                {
                    continue;
                }

                var role = new StringBuilder();
                foreach (var type in typeList)
                {
                    if (type.Contains("CN"))
                    {
                        var roleList = type.Split('=');
                        if (!role.ToString().Equals(""))
                        {
                            role.Append(",").Append(roleList[1]);
                        }
                        else
                        {
                            role.Append(roleList[1]);
                        }
                    }
                }

                return role.ToString();
            }

            return null;
        }
    }
}