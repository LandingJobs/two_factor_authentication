Warden::Manager.after_authentication do |user, auth, options|
  if auth.env["action_dispatch.cookies"]
    expected_cookie_value = "#{user.class}-#{user.public_send(Devise.second_factor_resource_id)}"
    name = TwoFactorAuthentication::remember_tfa_cookie_name(options[:scope])
    actual_cookie_value = auth.env["action_dispatch.cookies"].signed[name]
    bypass_by_cookie = actual_cookie_value == expected_cookie_value
  end

  if user.respond_to?(:need_two_factor_authentication?) && !bypass_by_cookie
    if auth.session(options[:scope])[TwoFactorAuthentication::NEED_AUTHENTICATION] = user.need_two_factor_authentication?(auth.request)
      user.send_new_otp if user.send_new_otp_after_login?
    end
  end
end

Warden::Manager.before_logout do |user, auth, options|
  if Devise.delete_cookie_on_logout
    name = TwoFactorAuthentication::remember_tfa_cookie_name(options[:scope])
    auth.cookies.delete name
  end
end
