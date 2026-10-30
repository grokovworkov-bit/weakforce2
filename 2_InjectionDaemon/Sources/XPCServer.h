/*
 * TweakForce — XPCServer.h (InjectionDaemon)
 * EN: CFMessagePort server "com.tweakforce.daemon". Commands: PING, GET_STATUS,
 *     SET_TWEAK_FOR_APP, INJECT_NOW, GET_LOG. Clients: Manager app, tweaks.
 * RU: Сервер CFMessagePort "com.tweakforce.daemon". Команды: PING, GET_STATUS,
 *     SET_TWEAK_FOR_APP, INJECT_NOW, GET_LOG. Клиенты: Manager app, tweaks.
 */
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@interface XPCServer : NSObject
+ (instancetype)shared;
/// Start listening on the given port name. / Начать слушать на имени порта.
- (BOOL)startWithPortName:(NSString *)portName;
- (void)stop;
@end
NS_ASSUME_NONNULL_END
