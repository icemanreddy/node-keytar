#include <Security/Security.h>
#include "keytar.h"
#include "credentials.h"
#include  <os/log.h>


namespace keytar {

/**
 * Converts a CFString to a std::string
 *
 * This either uses CFStringGetCStringPtr or (if that fails)
 * CFStringGetCString, trying to be as efficient as possible.
 */
const std::string CFStringToStdString(CFStringRef cfstring) {
  const char* cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

  if (cstr != NULL) {
    return std::string(cstr);
  }

  CFIndex length = CFStringGetLength(cfstring);
  // Worst case: 2 bytes per character + NUL
  CFIndex cstrPtrLen = length * 2 + 1;
  char* cstrPtr = static_cast<char*>(malloc(cstrPtrLen));

  Boolean result = CFStringGetCString(cfstring,
                                      cstrPtr,
                                      cstrPtrLen,
                                      kCFStringEncodingUTF8);

  std::string stdstring;
  if (result) {
    stdstring = std::string(cstrPtr);
  }

  free(cstrPtr);

  return stdstring;
}

const std::string errorStatusToString(OSStatus status) {
  std::string errorStr;
  CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

  const char* errorCStringPtr = CFStringGetCStringPtr(errorMessageString,
                                                      kCFStringEncodingUTF8);
  if (errorCStringPtr) {
    errorStr = std::string(errorCStringPtr);
  } else {
    errorStr = std::string("An unknown error occurred.");
  }

  CFRelease(errorMessageString);
  return errorStr;
}
//https://developer.apple.com/documentation/security/seckeychainpromptselector?language=objc
//https://developer.apple.com/documentation/security/1400997-secaclsetcontents?language=objc
//https://developer.apple.com/documentation/security/keychain_services/access_control_lists?language=objc
KEYTAR_OP_RESULT AddPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error){
 os_log(OS_LOG_DEFAULT, "Entered Add password");


  SecKeychainItemRef item_ref;
  OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                  service.length(),
                                                  service.data(),
                                                  account.length(),
                                                  account.data(),
                                                  password.length(),
                                                  password.data(),
                                                  &item_ref);


  os_log(OS_LOG_DEFAULT,"debug_Errno:%{errno}d",status);
  
    SecAccessRef accessref;
    SecKeychainItemCopyAccess (item_ref, &accessref);
    CFArrayRef aclList;
    SecAccessCopyACLList(accessref, &aclList);

    CFIndex count = CFArrayGetCount(aclList);
    os_log(OS_LOG_DEFAULT,"%ld lists\n", count);
    CFArrayRef zero_applications=CFArrayCreate (NULL,NULL,0,NULL);
  
    for (int i = 0; i < count; i++) {
        SecACLRef acl = (SecACLRef) CFArrayGetValueAtIndex(aclList, i);
        
        CFArrayRef applicationList;
        CFStringRef description;
        CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR promptSelector;
        SecACLCopySimpleContents (acl, &applicationList, &description,
                                  &promptSelector);
       if (applicationList == NULL) {
         continue;
       }
        CFIndex appCount = CFArrayGetCount(applicationList);
        os_log(OS_LOG_DEFAULT ,"\t\t%ld applications in list %d\n", appCount, i);

        for (int j = 0; j < appCount; j++) {
          status= SecACLSetContents(acl,zero_applications,description,1);
          //ACL modify in the copy accessref
          os_log(OS_LOG_DEFAULT ,"modified acl.status: %{errno}d",status);
       
        }
        CFRelease(applicationList);
    }

  //Set the modified copy to the item now
  status = SecKeychainItemSetAccess(item_ref,accessref);

  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error) {
SecKeychainItemRef item;
  OSStatus result = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);

  if (result == errSecItemNotFound) {
    return AddPassword(service, account, password, error);
  } else if (result != errSecSuccess) {
    *error = errorStatusToString(result);
    return FAIL_ERROR;
  }

  result = SecKeychainItemModifyAttributesAndData(item,
                                                  NULL,
                                                  password.length(),
                                                  password.data());
  CFRelease(item);
  if (result != errSecSuccess) {
    *error = errorStatusToString(result);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* error) {
  void *data;
  UInt32 length;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   &length,
                                                   &data,
                                                   NULL);

  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* error) {
  SecKeychainItemRef item;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);
  if (status == errSecItemNotFound) {
    // Item could not be found, so already deleted.
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  status = SecKeychainItemDelete(item);
  CFRelease(item);
  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* error) {
  SecKeychainItemRef item;
  void *data;
  UInt32 length;

  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   0,
                                                   NULL,
                                                   &length,
                                                   &data,
                                                   &item);
  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  CFRelease(item);
  return SUCCESS;
}

Credentials getCredentialsForItem(CFDictionaryRef item) {
  CFStringRef service = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrService);
  CFStringRef account = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrAccount);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(query, kSecAttrService, service);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecAttrAccount, account);

  CFTypeRef result;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  if (status == errSecSuccess) {
      CFDataRef passwordData = (CFDataRef) CFDictionaryGetValue(
        (CFDictionaryRef) result,
        CFSTR("v_Data"));
      CFStringRef password = CFStringCreateFromExternalRepresentation(
        NULL,
        passwordData,
        kCFStringEncodingUTF8);

      Credentials cred = Credentials(
        CFStringToStdString(account),
        CFStringToStdString(password));
      CFRelease(password);

      return cred;
  }

  return Credentials();
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(
    NULL,
    service.c_str(),
    kCFStringEncodingUTF8);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

  CFTypeRef result;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  if (status == errSecSuccess) {
    CFArrayRef resultArray = (CFArrayRef) result;
    int resultCount = CFArrayGetCount(resultArray);

    for (int idx = 0; idx < resultCount; idx++) {
      CFDictionaryRef item = (CFDictionaryRef) CFArrayGetValueAtIndex(
        resultArray,
        idx);

      Credentials cred = getCredentialsForItem(item);
      credentials->push_back(cred);
    }
  } else if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }


  if (result != NULL) {
    CFRelease(result);
  }

  CFRelease(query);

  return SUCCESS;
}

}  // namespace keytar
