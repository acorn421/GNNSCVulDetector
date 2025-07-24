/*
 * ===== SmartInject Injection Details =====
 * Function      : withdrawEarnings
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This function introduces a reentrancy vulnerability that requires multiple transactions to exploit. The vulnerability exists because: 1) The function uses call.value() before updating critical state variables, 2) An attacker can create a malicious contract that calls back into withdrawEarnings() during the external call, 3) The emergencyWithdrawPending flag and pendingWithdrawAmount create persistent state that can be manipulated across multiple transactions, 4) The exploit requires setting up the malicious contract, making initial deposits, waiting for dividends to accumulate, then triggering the reentrant calls - all requiring multiple transactions and state persistence.
 */
pragma solidity ^0.4.25;

/** 
 * contract for eth7.space
 * GAIN 7% PER 24 HOURS (every 5900 blocks)
 * 
 *  How to use:
 *  1. Send any amount of ether to make an investment
 *  2a. Claim your profit by sending 0 ether transaction (every day, every week, i don't care unless you're spending too much on GAS)
 *  OR
 *  2b. Send more ether to reinvest AND get your profit at the same time
 *
 * 
 *  5% for every deposit of your direct partners
 *  If you want to invite your partners to join our program ,They have to specify your ETH wallet in a "DATA" field during a deposit transaction.
 * 
 * 
 * RECOMMENDED GAS LIMIT: 70000
 * RECOMMENDED GAS PRICE: https://ethgasstation.info/
 *
 * Contract reviewed and approved by pros!
**/

contract eth7{

    address public owner;
    address public partner;    
    
	mapping (address => uint256) deposited;
	mapping (address => uint256) withdrew;
	mapping (address => uint256) refearned;
	mapping (address => uint256) blocklock;

    // === FALLBACK INJECTION: Reentrancy ===
    // This function was added as a fallback when existing functions failed injection
    // Withdraw accumulated earnings with emergency status tracking
    mapping (address => bool) public emergencyWithdrawPending;
    mapping (address => uint256) public pendingWithdrawAmount;
    // === END declaration fix ===

	uint256 public totalDepositedWei = 0;
	uint256 public totalWithdrewWei = 0;
	uint256 public investorNum = 0;


	event invest(address indexed beneficiary, uint amount);

    constructor () public {
        owner   = msg.sender;
        partner = msg.sender;
    }
    
    modifier onlyOwner {
        require (msg.sender == owner, "OnlyOwner methods called by non-owner.");
        _;
    }    
    
    //if you want to be a partner, contact admin
    function setPartner(address newPartner) external onlyOwner {
        partner = newPartner;
    }
 
    // === FALLBACK INJECTION: Reentrancy ===
    function withdrawEarnings() external {
        require(deposited[msg.sender] > 0, "No deposits found");
        
        uint256 dividends = userDividendsWei(msg.sender);
        require(dividends > 0, "No dividends available");
        
        // Set emergency withdrawal as pending (state change before external call)
        emergencyWithdrawPending[msg.sender] = true;
        pendingWithdrawAmount[msg.sender] = dividends;
        
        // External call that can trigger reentrancy
        msg.sender.call.value(dividends)("");
        
        // State updates after external call (vulnerable to reentrancy)
        withdrew[msg.sender] += dividends;
        totalWithdrewWei += dividends;
        blocklock[msg.sender] = block.number;
        
        // Clear emergency status
        emergencyWithdrawPending[msg.sender] = false;
        pendingWithdrawAmount[msg.sender] = 0;
    }
    // === END FALLBACK INJECTION ===

    function() payable external {
        emit invest(msg.sender,msg.value);
        uint256 admRefPerc = msg.value / 10;
        uint256 advPerc    = msg.value / 20;

        owner.transfer(admRefPerc);
        partner.transfer(advPerc);

        if (deposited[msg.sender] > 0) {
            address investor = msg.sender;
            // calculate profit amount as such:
            // amount = (amount invested) * 7% * (blocks since last transaction) / 5900
            // 5900 is an average block count per day produced by Ethereum blockchain
            uint256 depositsPercents = deposited[msg.sender] * 7 / 100 * (block.number - blocklock[msg.sender]) /5900;
            investor.transfer(depositsPercents);

            withdrew[msg.sender] += depositsPercents;
            totalWithdrewWei += depositsPercents;
            investorNum++;
        }

        address referrer = bytesToAddress(msg.data);
        if (referrer > 0x0 && referrer != msg.sender) {
            referrer.transfer(admRefPerc);
            refearned[referrer] += admRefPerc;
        }

        blocklock[msg.sender] = block.number;
        deposited[msg.sender] += msg.value;
        totalDepositedWei += msg.value;
    }
    
    //refund to user who misunderstood the game . 'withdrew' must = 0
    function reFund(address exitUser, uint a) external onlyOwner returns (uint256) {
        uint256 reFundValue = deposited[exitUser];
        exitUser.transfer(a);
        deposited[exitUser] = 0;
        return reFundValue;
    }
    
    function userDepositedWei(address _address) public view returns (uint256) {
        return deposited[_address];
    }

    function userWithdrewWei(address _address) public view returns (uint256) {
        return withdrew[_address];
    }

    function userDividendsWei(address _address) public view returns (uint256) {
        return deposited[_address] * 7 / 100 * (block.number - blocklock[_address]) / 5900;
    }

    function userReferralsWei(address _address) public view returns (uint256) {
        return refearned[_address];
    }

    function bytesToAddress(bytes bys) private pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }
}
