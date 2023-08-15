import {
  Update,
  Start,
  Ctx,
  On,
  Hears,
  Command,
  Action,
} from 'nestjs-telegraf';
import { BotService } from './bot.service';
import { Context, Markup } from 'telegraf';

@Update()
export class BotUpdate {
  constructor(private readonly botService: BotService) {}

  @Start()
  async onStart(@Ctx() ctx: Context) {
    return this.botService.start(ctx);
  }

  @On('contact')
  async onContact(@Ctx() ctx: Context) {
    return this.botService.onContact(ctx);
  }

  @Command('stop')
  async onStop(@Ctx() ctx: Context) {
    return this.botService.onStop(ctx);
  }

  // @On('photo')
  // async onPhoto(@Ctx() ctx: Context) {
  //   if ('photo' in ctx.message) {
  //     console.log(ctx.message.photo);
  //     await ctx.replyWithPhoto(
  //       String(ctx.message.photo[ctx.message.photo.length - 1].file_id),
  //     );
  //   }
  // }

  // @On('video')
  // async onVideo(@Ctx() ctx: Context) {
  //   if ('video' in ctx.message) {
  //     await ctx.reply(String(ctx.message.video.file_name));
  //   }
  // }

  // @On('sticker')
  // async onSticker(@Ctx() ctx: Context) {
  //   if ('sticker' in ctx.message) {
  //     await ctx.reply('👍');
  //   }
  // }

  // @On('animation')
  // async onAnimation(@Ctx() ctx: Context) {
  //   if ('animation' in ctx.message) {
  //     await ctx.reply('animate');
  //   }
  // }

  // @On('contact')
  // async onContact(@Ctx() ctx: Context) {
  //   if ('contact' in ctx.message) {
  //     await ctx.reply(String(ctx.message.contact.phone_number));
  //     await ctx.reply(String(ctx.message.contact.first_name));
  //     await ctx.reply(String(ctx.message.contact.last_name));
  //     await ctx.reply(String(ctx.message.contact.user_id));
  //   }
  // }
  // @On('location')
  // async onLocation(@Ctx() ctx: Context) {
  //   if ('location' in ctx.message) {
  //     await ctx.reply(String(ctx.message.location.latitude));
  //     await ctx.reply(String(ctx.message.location.longitude));
  //   }
  // }
  // @On('channel_post')
  // async onChannel_Post(@Ctx() ctx: Context) {
  //   if ('channel_post' in ctx.message) {
  //     await ctx.reply(String(ctx.message.channel_post));
  //   }
  // }
  // // telegram orqali tolov amalga oshirish uchun
  // @On('invoice')
  // async oninvoice(@Ctx() ctx: Context) {
  //   if ('invoice' in ctx.message) {
  //     await ctx.reply(String(ctx.message.invoice.title));
  //   }
  // }

  // // telegram orqali tolov amalga oshirish uchun
  // @On('voice')
  // async onvoice(@Ctx() ctx: Context) {
  //   if ('voice' in ctx.message) {
  //     await ctx.reply(String(ctx.message.voice.duration));
  //   }
  // }

  // @On('document')
  // async ondocument(@Ctx() ctx: Context) {
  //   if ('document' in ctx.message) {
  //     await ctx.reply(String(ctx.message.document.file_name));
  //   }
  // }

  // @On('venue')
  // async onvenue(@Ctx() ctx: Context) {
  //   if ('venue' in ctx.message) {
  //     await ctx.reply(String(ctx.message.venue.address));
  //   }
  // }

  // @Hears('hi')
  // async hears(@Ctx() ctx: Context) {
  //   await ctx.reply('Hey there');
  // }
  // @Command('info')
  // async info(@Ctx() ctx: Context) {
  //   await ctx.reply('Information');
  // }
  // @Command('inline_keyboard')
  // async inlineButton(@Ctx() ctx: Context) {
  //   const inlineKeyboard = [
  //     [
  //       { text: 'Button 1', callback_data: 'button1' },
  //       { text: 'Button 2', callback_data: 'button2' },
  //       { text: 'Button 3', callback_data: 'button3' },
  //     ],
  //     [{ text: 'Button 4', callback_data: 'button4' }],
  //     [{ text: 'Button 5', callback_data: 'button5' }],
  //   ];
  //   ctx.reply('Choose a inline button:', {
  //     reply_markup: {
  //       inline_keyboard: inlineKeyboard,
  //     },
  //   });
  // }

  // @Action('button1')
  // async onActionButton1(@Ctx() ctx: Context) {
  //   ctx.reply('You pressed Button 1!');
  // }
  // @Action('button2')
  // async onActionButton2(@Ctx() ctx: Context) {
  //   ctx.reply('You pressed Button 2!');
  // }
  // @Action('button3')
  // async onActionButton3(@Ctx() ctx: Context) {
  //   ctx.reply('You pressed Button 3!');
  // }
  // @Action('button4')
  // async onActionButton4(@Ctx() ctx: Context) {
  //   ctx.reply('You pressed Button 4!');
  // }
  // @Action('button5')
  // async onActionButton5(@Ctx() ctx: Context) {
  //   ctx.reply('You pressed Button 5!');
  // }
  // @Command('main_keyboard')
  // async mainButton(@Ctx() ctx: Context) {
  //   ctx.reply(`Choose a main button:`, {
  //     parse_mode: 'HTML',
  //     ...Markup.keyboard([
  //       ['bir', 'ikki', 'uch'],
  //       ["to'rt"],
  //       [Markup.button.contactRequest('📞 Telefon raqamni yuborish')],
  //       [Markup.button.locationRequest('📍 Location yuborish')],
  //     ])
  //       .oneTime()
  //       .resize(),
  //   });
  // }
  // @Hears('bir')
  // async onBirButton(@Ctx() ctx: Context) {
  //   ctx.reply('bir bosildi');
  // }
  // @Hears('ikki')
  // async onIkkiButton(@Ctx() ctx: Context) {
  //   ctx.reply('ikki bosildi');
  // }
  // @Hears('uch')
  // async onUchButton(@Ctx() ctx: Context) {
  //   ctx.reply('uch bosildi');
  // }
  // @Hears("to'rt")
  // async onTortButton(@Ctx() ctx: Context) {
  //   ctx.reply("to'rt bosildi");
  // }

  // @On('message')
  // OnMessage(ctx: Context) {
  //   // @ts-ignore
  //   const text = ctx.message.text
  //   if(text=="salom"){
  //     return "hello"
  //   }
  //   return text;
  // }
}
