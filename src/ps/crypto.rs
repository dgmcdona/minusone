
use crate::ps::{PSObject, Powershell};
use crate::rule::RuleMut;
// use crate::scope::ScopeManager;
use crate::tree::Node;

#[derive(Debug, Clone, Default)]
pub struct CryptoObjectUse {
    // scope_mgr: ScopeManager<Powershell>,
}

const AES: &str = "system.security.cryptography.aes";

trait SingleChild<T> {
    fn single_child(self, kind: &str) -> Option<T>;
}

impl<'a> SingleChild<Node<'a, Powershell>> for Node<'a, Powershell> {
    fn single_child(self, kind: &str) -> Option<Node<'a, Powershell>> {
        if self.child_count() != 1 {
            return None;
        }
        if let Some(child) = self.child(0) {
            if child.kind() == kind {
                return Some(child);
            }
        }
        None
    }
}

impl<'a> RuleMut<'a> for CryptoObjectUse {
    type Language = Powershell;

    fn enter(
        &mut self,
        _node: &mut crate::tree::NodeMut<'a, Self::Language>,
        _flow: crate::tree::ControlFlow,
    ) -> crate::error::MinusOneResult<()> {
        // todo!()
        Ok(())
    }

    fn leave(
        &mut self,
        node: &mut crate::tree::NodeMut<'a, Self::Language>,
        _flow: crate::tree::ControlFlow,
    ) -> crate::error::MinusOneResult<()> {
        let view = node.view();

        println!("Level 0");
        if view.kind() == "invokation_expression" && view.child_count() == 4 {
            println!("Level 1");
            if let (Some(typnode), Some(op), Some(member), Some(arglist)) =
                (view.child(0), view.child(1), view.child(2), view.child(3))
            {
                println!("Level 2");
                if let (Some(Powershell::Type(typename)), Ok(operator), Ok(membername)) = (typnode.data(), op.text(), member.text()) {
                    println!("Level 3");
                    if typename.to_lowercase() == AES
                        && member.kind() == "member_name"
                        && membername.to_lowercase() == "create"
                        && operator.to_lowercase() == "::"
                        && arglist.child_count() == 2 // open/close parens
                    {
                        println!("Level 4");
                        node.set(Powershell::Object(PSObject::new(AES)));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    const CASE: &str = include_str!("../../testdata/peaklight.ps1");

    #[test]
    fn test_crypto_create() {
    }
}
