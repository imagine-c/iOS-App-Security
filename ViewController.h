//
//  ViewController.h
//  iOS-App-Security
//
//  Created by karek314 on 13/10/16.
//  Copyright © 2016 karek314. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController<UITextViewDelegate>

- (IBAction)check:(id)sender;
+(void)updateTextFieldClass;
@property (weak, nonatomic) IBOutlet UITextView *textField;

@end

