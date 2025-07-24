/*
 * ===== SmartInject Injection Details =====
 * Function      : setPromoToPartner
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **Specific Changes Made:**
 * 1. **Split State Updates**: Divided the state modification into two stages with external calls between them
 * 2. **Added External Validation Call**: Inserted `validator.validatePromoCode(promo, msg.sender)` between partial state updates
 * 3. **Added External Notification Call**: Added `notifyPartnerRegistered()` call after final state update
 * 4. **Created Reentrancy Window**: The external calls occur when state is partially updated but not fully committed
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Initial Attack Setup):**
 * - Attacker deploys malicious contract implementing `IPromoValidator` interface
 * - Attacker calls `setPromoToPartner("HACK01")` 
 * - Function executes up to `validator.validatePromoCode()` call
 * - At this point: `partnersPromo["HACK01"] = attacker`, `partnersInfo[attacker].create = false` (still false!)
 * 
 * **Transaction 2 (Reentrancy Attack):**
 * - During `validator.validatePromoCode()` external call, malicious validator contract re-enters
 * - Malicious contract calls `setPromoToPartner("HACK02")` 
 * - Second call passes `assert(partnersInfo[msg.sender].create==false)` because it's still false
 * - This allows attacker to register multiple promo codes for the same address
 * 
 * **Transaction 3 (State Exploitation):**
 * - Attacker exploits the inconsistent state in subsequent calls to `add_referral()` 
 * - Can potentially claim bonuses for multiple promo codes
 * - Or manipulate `attracted_investments` calculations across different promo registrations
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Persistence**: The vulnerability depends on persistent state changes between transactions
 * 2. **External Contract Dependency**: Requires deploying and controlling external validator contract
 * 3. **Timing Window**: The reentrancy window only exists during external call execution
 * 4. **Accumulated State**: Exploitation requires building up inconsistent state across multiple registrations
 * 5. **Cross-Function Impact**: The vulnerability's impact is realized in other functions like `add_referral()` that depend on the corrupted state
 * 
 * **Realistic Integration:**
 * - Promo code validation is a legitimate business requirement
 * - Notification systems are common in production contracts
 * - The external calls appear natural and would likely pass code review
 * - The vulnerability is subtle and would be difficult to detect without thorough security analysis
 */
pragma solidity ^0.4.15;

// Interface for external PromoValidator contract
interface IPromoValidator {
    function validatePromoCode(string promo, address sender) external returns (bool);
}

// Interface for external NotificationService contract
interface INotificationService {
    function notifyPartnerRegistered(address partner, string promo) external;
}

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
    // Declare missing addresses for external contracts
    address public validatorContract;
    address public notificationContract;

    function BMICOAffiliateProgramm() public {
        owner = msg.sender;
        contractPreICO = address(0x0);
        contractICO = address(0x0);
        validatorContract = address(0x0);
        notificationContract = address(0x0);
    }

    modifier isOwner()
    {
        assert(msg.sender == owner);
        _;
    }

    function setValidatorContract(address _validator) isOwner public {
        require(_validator != address(0x0));
        validatorContract = _validator;
    }

    function setNotificationContract(address _notifier) isOwner public {
        require(_notifier != address(0x0));
        notificationContract = _notifier;
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

    function setPromoToPartner(string promo) public {
        assert(partnersPromo[promo]==address(0x0));
        assert(partnersInfo[msg.sender].create==false);
        assert(str_length(promo)>0 && str_length(promo)<=6);

        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Stage 1: Initialize partner registration state
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        partnersPromo[promo] = msg.sender;
        partnersInfo[msg.sender].attracted_investments = 0;
        partnersInfo[msg.sender].promo = promo;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to validate promo code before finalizing registration
        // This creates a reentrancy window where state is partially updated
        IPromoValidator validator = IPromoValidator(validatorContract);
        require(validator.validatePromoCode(promo, msg.sender));
        
        // Stage 2: Finalize partner registration (vulnerable to reentrancy)
        partnersInfo[msg.sender].create = true;
        
        // External notification after registration completion
        INotificationService(notificationContract).notifyPartnerRegistered(msg.sender, promo);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
                referralsInfo[referral].amount_investments += amount;
                amount_referral_invest += amount;
                partnersInfo[partner].attracted_investments += amount;
                history[partner].push(itemHistory(now, referral, amount));
                p_partner = (amount*uint256(calc_partnerPercent(partner)))/10000;
                p_referral = (amount*uint256(ref_percent))/10000;
            }
        }
    }
}
