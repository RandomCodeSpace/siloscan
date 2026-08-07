// Expansion of #[derive(Serialize, Deserialize)] for DbConfig, captured with
// `cargo expand config::db > src/generated/expanded.rs` and committed so the
// derive output can be diffed across serde upgrades.  Not compiled into the
// crate; see build.rs.
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for DbConfig {
        fn serialize<__S>(&self, __serializer: __S) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = _serde::Serializer::serialize_struct(
                __serializer,
                "DbConfig",
                false as usize + 1 + 1 + 1 + 1,
            )?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "host", &self.host)?;
            _serde::ser::SerializeStruct::serialize_field(&mut __serde_state, "port", &self.port)?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "password",
                &self.password,
            )?;
            _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "api_key",
                &self.api_key,
            )?;
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for DbConfig {
        fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __field2,
                __field3,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "host" => _serde::__private::Ok(__Field::__field0),
                        "port" => _serde::__private::Ok(__Field::__field1),
                        "password" => _serde::__private::Ok(__Field::__field2),
                        "api_key" => _serde::__private::Ok(__Field::__field3),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"host" => _serde::__private::Ok(__Field::__field0),
                        b"port" => _serde::__private::Ok(__Field::__field1),
                        b"password" => _serde::__private::Ok(__Field::__field2),
                        b"api_key" => _serde::__private::Ok(__Field::__field3),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            #[doc(hidden)]
            const FIELDS: &[&str] = &["host", "port", "password", "api_key"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "DbConfig",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<DbConfig>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
