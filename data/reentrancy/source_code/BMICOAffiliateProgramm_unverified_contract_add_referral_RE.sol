/*
 * ===== SmartInject Injection Details =====
 * Function      : add_referral
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to partner and referral addresses before final bonus state updates. The vulnerability exploits the persistent state accumulation across transactions and requires multiple calls to be effectively exploited.
 * 
 * **Specific Changes Made:**
 * 1. Added external calls to partner and referral addresses using low-level `call()` function
 * 2. Moved final bonus state updates (preico_partnerBonus and preico_holdersBonus) to occur AFTER external calls
 * 3. Added code.length checks to make external calls realistic (only call if target is a contract)
 * 4. Used realistic function signatures for bonus notifications that would naturally exist in an affiliate system
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls add_referral with legitimate parameters, setting up initial state
 * 2. **During external call**: When the contract calls partner.notifyPartnerBonus(), the attacker's malicious partner contract re-enters add_referral
 * 3. **Reentrancy**: The re-entered call sees the already-updated state variables (amount_investments, attracted_investments) but hasn't yet updated the bonus amounts
 * 4. **Transaction 2**: The attacker can manipulate the bonus calculations by calling add_referral again with different parameters during the reentrancy
 * 5. **State Accumulation**: The vulnerability leverages the persistent state changes across multiple transactions to double-count bonuses or manipulate partner statistics
 * 
 * **Why Multi-Transaction Requirement:**
 * - The vulnerability requires the accumulation of state changes across multiple add_referral calls
 * - The attacker needs to first establish legitimate referral relationships and investment amounts in earlier transactions
 * - The exploit depends on the persistent state (partnersInfo, referralsInfo) that builds up over time
 * - The reentrancy attack manipulates the timing between state updates and external calls, requiring multiple transaction contexts
 * - The bonus calculations depend on historical data (attracted_investments) that must be built up through multiple legitimate transactions before exploitation
 * 
 * The vulnerability is realistic because affiliate programs commonly notify partners about bonuses, and the state management complexity creates natural opportunities for checks-effects-interactions violations.
 */
pragma solidity ^0.4.15;

contract BMICOAffiliateProgramm {
    struct itemReferrals {
        uint256 amount_investments;
        uint256 preico_holdersBonus;
    }
    mapping (address => itemReferrals) referralsInfo;
    uint256 public preico_holdersAmountInvestWithBonus = 0;

    mapping (string => address) partnersPromo;
    struct itemPartners {
        uint256 attracted_investments;
        string promo;
        uint16 personal_percent;
        uint256 preico_partnerBonus;
        bool create;
    }
    mapping (address => itemPartners) partnersInfo;

    uint16 public ref_percent = 100; //1 = 0.01%, 10000 = 100%

    struct itemHistory {
        uint256 datetime;
        address referral;
        uint256 amount_invest;
    }
    mapping(address => itemHistory[]) history;

    uint256 public amount_referral_invest;

    address public owner;
    address public contractPreICO;
    address public contractICO;

    constructor(){
        owner = msg.sender;
        contractPreICO = address(0x0);
        contractICO = address(0x0);
    }

    modifier isOwner()
    {
        assert(msg.sender == owner);
        _;
    }

    function str_length(string x) constant internal returns (uint256) {
        bytes32 str;
        assembly {
        str := mload(add(x, 32))
        }
        bytes memory bytesString = new bytes(32);
        uint256 charCount = 0;
        for (uint j = 0; j < 32; j++) {
            byte char = byte(bytes32(uint(str) * 2 ** (8 * j)));
            if (char != 0) {
                bytesString[charCount] = char;
                charCount++;
            }
        }
        return charCount;
    }

    function changeOwner(address new_owner) isOwner {
        assert(new_owner!=address(0x0));
        assert(new_owner!=address(this));

        owner = new_owner;
    }

    function setReferralPercent(uint16 new_percent) isOwner {
        ref_percent = new_percent;
    }

    function setPartnerPercent(address partner, uint16 new_percent) isOwner {
        assert(partner!=address(0x0));
        assert(partner!=address(this));
        assert(partnersInfo[partner].create==true);
        partnersInfo[partner].personal_percent = new_percent;
    }

    function setContractPreICO(address new_address) isOwner {
        assert(contractPreICO==address(0x0));
        assert(new_address!=address(0x0));
        assert(new_address!=address(this));

        contractPreICO = new_address;
    }

    function setContractICO(address new_address) isOwner {
        assert(contractICO==address(0x0));
        assert(new_address!=address(0x0));
        assert(new_address!=address(this));

        contractICO = new_address;
    }

    function setPromoToPartner(string promo) {
        assert(partnersPromo[promo]==address(0x0));
        assert(partnersInfo[msg.sender].create==false);
        assert(str_length(promo)>0 && str_length(promo)<=6);

        partnersPromo[promo] = msg.sender;
        partnersInfo[msg.sender].attracted_investments = 0;
        partnersInfo[msg.sender].promo = promo;
        partnersInfo[msg.sender].create = true;
    }

    function checkPromo(string promo) constant returns(bool){
        return partnersPromo[promo]!=address(0x0);
    }

    function checkPartner(address partner_address) constant returns(bool isPartner, string promo){
        isPartner = partnersInfo[partner_address].create;
        promo = '-1';
        if(isPartner){
            promo = partnersInfo[partner_address].promo;
        }
    }

    function calc_partnerPercent(address partner) constant internal returns(uint16 percent){
        percent = 0;
        if(partnersInfo[partner].personal_percent > 0){
            percent = partnersInfo[partner].personal_percent;
        }
        else{
            uint256 attracted_investments = partnersInfo[partner].attracted_investments;
            if(attracted_investments > 0){
                if(attracted_investments < 3 ether){
                    percent = 300; //1 = 0.01%, 10000 = 100%
                }
                else if(attracted_investments >= 3 ether && attracted_investments < 10 ether){
                    percent = 500;
                }
                else if(attracted_investments >= 10 ether && attracted_investments < 100 ether){
                    percent = 700;
                }
                else if(attracted_investments >= 100 ether){
                    percent = 1000;
                }
            }
        }
    }

    function partnerInfo(address partner_address) isOwner constant returns(string promo, uint256 attracted_investments, uint256[] h_datetime, uint256[] h_invest, address[] h_referrals){
        if(partner_address != address(0x0) && partnersInfo[partner_address].create){
            promo = partnersInfo[partner_address].promo;
            attracted_investments = partnersInfo[partner_address].attracted_investments;

            h_datetime = new uint256[](history[partner_address].length);
            h_invest = new uint256[](history[partner_address].length);
            h_referrals = new address[](history[partner_address].length);

            for(uint256 i=0; i<history[partner_address].length; i++){
                h_datetime[i] = history[partner_address][i].datetime;
                h_invest[i] = history[partner_address][i].amount_invest;
                h_referrals[i] = history[partner_address][i].referral;
            }
        }
        else{
            promo = '-1';
            attracted_investments = 0;
            h_datetime = new uint256[](0);
            h_invest = new uint256[](0);
            h_referrals = new address[](0);
        }
    }

    function refferalPreICOBonus(address referral) constant external returns (uint256 bonus){
        bonus = referralsInfo[referral].preico_holdersBonus;
    }

    function partnerPreICOBonus(address partner) constant external returns (uint256 bonus){
        bonus = partnersInfo[partner].preico_partnerBonus;
    }

    function referralAmountInvest(address referral) constant external returns (uint256 amount){
        amount = referralsInfo[referral].amount_investments;
    }

    // Assembly function to get code size (compatible with Solidity ^0.4.15)
    function extcodesizeOf(address _addr) internal view returns (uint codeSize) {
        assembly { codeSize := extcodesize(_addr) }
    }

    function add_referral(address referral, string promo, uint256 amount) external returns(address partner, uint256 p_partner, uint256 p_referral){
        p_partner = 0;
        p_referral = 0;
        partner = address(0x0);
        if(partnersPromo[promo] != address(0x0) && partnersPromo[promo] != referral){
            partner = partnersPromo[promo];
            if(msg.sender == contractPreICO){
                referralsInfo[referral].amount_investments += amount;
                amount_referral_invest += amount;
                partnersInfo[partner].attracted_investments += amount;
                history[partner].push(itemHistory(now, referral, amount));

                uint256 partner_bonus = (amount*uint256(calc_partnerPercent(partner)))/10000;
                if(partner_bonus > 0){
                    partnersInfo[partner].preico_partnerBonus += partner_bonus;
                }
                uint256 referral_bonus = (amount*uint256(ref_percent))/10000;
                if(referral_bonus > 0){
                    referralsInfo[referral].preico_holdersBonus += referral_bonus;
                    preico_holdersAmountInvestWithBonus += amount;
                }
            }
            if (msg.sender == contractICO){
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Update state first
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                referralsInfo[referral].amount_investments += amount;
                amount_referral_invest += amount;
                partnersInfo[partner].attracted_investments += amount;
                history[partner].push(itemHistory(now, referral, amount));
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
                // Calculate bonuses
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                p_partner = (amount*uint256(calc_partnerPercent(partner)))/10000;
                p_referral = (amount*uint256(ref_percent))/10000;
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
                // Notify partner about new referral bonus - VULNERABLE: External call before final state update
                if(p_partner > 0){
                    // Check if partner has bonus notification enabled
                    uint partner_code_length = extcodesizeOf(partner);
                    if(partner_code_length > 0){
                        // External call to partner contract for bonus notification
                        // This allows reentrancy before final bonus accounting
                        bool successPartner;
                        (successPartner, ) = partner.call(abi.encodeWithSignature("notifyPartnerBonus(uint256,address,uint256)", p_partner, referral, amount));
                        // Continue regardless of success to maintain functionality
                    }
                }
        
                // Notify referral about bonus - VULNERABLE: Another external call opportunity
                if(p_referral > 0){
                    uint referral_code_length = extcodesizeOf(referral);
                    if(referral_code_length > 0){
                        bool successReferral;
                        (successReferral, ) = referral.call(abi.encodeWithSignature("notifyReferralBonus(uint256,address,uint256)", p_referral, partner, amount));
                        // Continue regardless of success
                    }
                }
        
                // Final state update happens AFTER external calls - VULNERABLE
                // This creates a window where state can be manipulated during reentrancy
                partnersInfo[partner].preico_partnerBonus += p_partner;
                referralsInfo[referral].preico_holdersBonus += p_referral;
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            }
        }
    }
}
