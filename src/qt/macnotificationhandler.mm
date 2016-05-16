#include "macnotificationhandler.h"

#undef slots
#include <Cocoa/Cocoa.h>

void MacNotificationHandler::showNotification(const QString &title, const QString &text) {

    /* Notification Center of MacOS X 10.8+ */
    if(this->hasNCenter()) {
        QByteArray utf8 = title.toUtf8();
        char *cString = (char *) utf8.constData();
        NSString *titleMac = [[NSString alloc] initWithUTF8String:cString];

        utf8 = text.toUtf8();
        cString = (char *) utf8.constData();
        NSString *textMac = [[NSString alloc] initWithUTF8String:cString];

        id userNotification = [[NSClassFromString(@"NSUserNotification") alloc] init];
        [userNotification performSelector:@selector(setTitle:) withObject:titleMac];
        [userNotification performSelector:@selector(setInformativeText:) withObject:textMac];

        id notificationCenterInstance = [NSClassFromString(@"NSUserNotificationCenter") performSelector:@selector(defaultUserNotificationCenter)];
        [notificationCenterInstance performSelector:@selector(deliverNotification:) withObject:userNotification];

        [titleMac release];
        [textMac release];
        [userNotification release];
    }
}

void MacNotificationHandler::sendAppleScript(const QString &script) {
    QByteArray utf8 = script.toUtf8();
    char *cString = (char *) utf8.constData();
    NSString *scriptApple = [[NSString alloc] initWithUTF8String:cString];

    NSAppleScript *as = [[NSAppleScript alloc] initWithSource:scriptApple];
    NSDictionary *err = nil;
    [as executeAndReturnError:&err];
    [as release];
    [scriptApple release];
}

bool MacNotificationHandler::hasNCenter(void) {

    if(NSClassFromString(@"NSUserNotificationCenter") != nil) return(true);

    return(false);
}

MacNotificationHandler *MacNotificationHandler::instance() {
    static MacNotificationHandler *s_instance = NULL;

    if(!s_instance)
      s_instance = new MacNotificationHandler();

    return(s_instance);
}
