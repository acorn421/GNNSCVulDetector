/*
 * ===== SmartInject Injection Details =====
 * Function      : add_referral
 * Vulnerability : Timestamp Dependence
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
 * Injected timestamp dependence vulnerability through multiple time-based mechanisms:
 * 
 * 1. **Multi-Transaction Time Window Manipulation**: Added logic that provides 50% bonus to partners who have investments within 24 hours of each other. This creates a stateful vulnerability where attackers can manipulate the timing of transactions across multiple blocks to consistently trigger bonus conditions.
 * 
 * 2. **Block Number Pseudo-Randomness**: Introduced block.number-based bonus multipliers (1-10x) for referral bonuses. This creates predictable patterns that attackers can exploit by timing their transactions to land in favorable block numbers, requiring multiple transactions to accumulate maximum bonuses.
 * 
 * 3. **Persistent State Dependency**: The vulnerability leverages the stored timestamp history and accumulated investment amounts, making it impossible to exploit in a single transaction. Attackers must:
 *    - First transaction: Make initial investment to establish state
 *    - Second transaction: Exploit timing windows for bonus calculations
 *    - Additional transactions: Accumulate bonuses by manipulating block timing
 * 
 * 4. **Cross-Phase Consistency**: Applied the same vulnerable logic to both PreICO and ICO phases, ensuring the vulnerability persists across different contract states.
 * 
 * The vulnerability is stateful because it depends on:
 * - Historical investment timestamps stored in the history array
 * - Accumulated investment amounts in referralsInfo
 * - Block number progression between transactions
 * 
 * This creates a realistic attack scenario where sophisticated attackers can time their transactions to maximize bonuses through timestamp manipulation across multiple blocks.
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

    function BMICOAffiliateProgramm(){
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

    function add_referral(address referral, string promo, uint256 amount) external returns(address partner, uint256 p_partner, uint256 p_referral){
        // Cache some storage variable references to avoid stack too deep
        itemReferrals storage rInfo = referralsInfo[referral];
        itemPartners storage pInfo = partnersInfo[partnersPromo[promo]];

        p_partner = 0;
        p_referral = 0;
        partner = address(0x0);
        if(partnersPromo[promo] != address(0x0) && partnersPromo[promo] != referral){
            partner = partnersPromo[promo];
            if(msg.sender == contractPreICO){
                rInfo.amount_investments += amount;
                amount_referral_invest += amount;
                pInfo.attracted_investments += amount;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

                // Store the timestamp of the investment for time-based bonus calculations
                uint256 investment_timestamp = now;
                history[partner].push(itemHistory(investment_timestamp, referral, amount));
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====

                uint256 partner_bonus = (amount*uint256(calc_partnerPercent(partner)))/10000;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

                // Apply early bird bonus if partner has recent activity within 24 hours
                if(history[partner].length > 1){
                    uint256 last_investment_time = history[partner][history[partner].length - 2].datetime;
                    if(investment_timestamp - last_investment_time <= 86400){ // 24 hours in seconds
                        partner_bonus = (partner_bonus * 150) / 100; // 50% bonus for frequent activity
                    }
                }

                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                if(partner_bonus > 0){
                    pInfo.preico_partnerBonus += partner_bonus;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

                uint256 referral_bonus = (amount*uint256(ref_percent))/10000;

                // Apply time-based referral bonus - higher bonus for investments made in same block
                if(referral_bonus > 0){
                    // Check if referral has invested in the same block (block.timestamp)
                    if(rInfo.amount_investments > 0){
                        // Use block.number as additional entropy for bonus calculation
                        uint256 block_bonus_multiplier1 = (block.number % 10) + 1; // 1-10x multiplier
                        referral_bonus = (referral_bonus * block_bonus_multiplier1) / 5; // Average 2x multiplier
                    }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
                    rInfo.preico_holdersBonus += referral_bonus;
                    preico_holdersAmountInvestWithBonus += amount;
                }
            }
            if (msg.sender == contractICO){
                rInfo.amount_investments += amount;
                amount_referral_invest += amount;
                pInfo.attracted_investments += amount;
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====

                uint256 investment_timestamp2 = now;
                history[partner].push(itemHistory(investment_timestamp2, referral, amount));

                p_partner = (amount*uint256(calc_partnerPercent(partner)))/10000;

                // Apply time-based partner bonus during ICO phase
                if(history[partner].length > 1){
                    uint256 last_investment_time2 = history[partner][history[partner].length - 2].datetime;
                    if(investment_timestamp2 - last_investment_time2 <= 86400){ // 24 hours
                        p_partner = (p_partner * 150) / 100; // 50% bonus
                    }
                }

                p_referral = (amount*uint256(ref_percent))/10000;

                // Time-dependent referral bonus using block properties
                if(rInfo.amount_investments > 0){
                    uint256 block_bonus_multiplier2 = (block.number % 10) + 1;
                    p_referral = (p_referral * block_bonus_multiplier2) / 5;
                }
                // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            }
        }
    }
}
