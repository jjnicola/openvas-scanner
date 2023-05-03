// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use rocket::launch;
use scanner_api::webserver::Webserver;

#[launch]
fn rocket() -> _ {
    let ws = Webserver::default();
    ws.run()
}