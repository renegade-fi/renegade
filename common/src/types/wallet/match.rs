//! Match settlement helpers

use circuit_types::{native_helpers::create_wallet_shares_from_private, r#match::MatchResult};
use util::matching_engine::compute_fee_obligation;

use super::{OrderIdentifier, Wallet};

impl Wallet {
    /// Settle a match on the given order into the wallet
    pub fn apply_match(
        &mut self,
        match_res: &MatchResult,
        order_id: &OrderIdentifier,
    ) -> Result<(), String> {
        // Subtract the matched volume from the order
        let match_fee = self.match_fee;
        let order = self.get_order_mut(order_id).unwrap();
        order.amount =
            order.amount.checked_sub(match_res.base_amount).expect("order volume underflow");

        // Select the correct mints and amounts based on the order side
        let (send_mint, send_amt) = match_res.send_mint_amount(order.side);
        let (recv_mint, recv_amt) = match_res.receive_mint_amount(order.side);
        let fees = compute_fee_obligation(match_fee, order.side, match_res);
        let net_recv = recv_amt - fees.total();

        // Update the balances
        let send_balance = self.get_balance_mut(&send_mint).unwrap();
        send_balance.amount = send_balance.amount.checked_sub(send_amt).expect("balance underflow");

        let recv_balance = self.get_balance_mut_or_default(&recv_mint);
        recv_balance.amount = recv_balance.amount.checked_add(net_recv).expect("balance overflow");
        recv_balance.relayer_fee_balance = recv_balance
            .relayer_fee_balance
            .checked_add(fees.relayer_fee)
            .expect("relayer fee balance overflow");
        recv_balance.protocol_fee_balance = recv_balance
            .protocol_fee_balance
            .checked_add(fees.protocol_fee)
            .expect("protocol fee balance overflow");

        // Update the public shares of the wallet, reblinding the wallet should be done
        // separately
        let (_, new_public_share) = create_wallet_shares_from_private(
            &self.clone().into(),
            &self.private_shares,
            self.blinder,
        );
        self.blinded_public_shares = new_public_share;

        // Invalidate the Merkle opening
        self.invalidate_merkle_opening();
        Ok(())
    }
}
