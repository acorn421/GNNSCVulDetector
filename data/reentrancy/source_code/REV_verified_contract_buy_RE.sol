/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 9 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-eth (SWC-107)
 * 3. reentrancy-benign (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Injected a stateful, multi-transaction reentrancy vulnerability that requires multiple function calls to exploit. The vulnerability stems from:
 * 
 * 1. **State Accumulation Requirements**: The function now uses `pendingPurchases` mapping that accumulates across multiple transactions, and includes a time-based delay (`PURCHASE_DELAY`) that requires at least two separate transactions spaced apart.
 * 
 * 2. **Vulnerable External Call Pattern**: The function performs an external call to the referrer address BEFORE finalizing all state changes, creating a reentrancy window. The `contract_balance` is updated early, but token finalization happens after the external call.
 * 
 * 3. **Multi-Transaction Exploitation Sequence**:
 *    - **Transaction 1**: Attacker calls `buy()` with malicious referrer contract, `contract_balance` increases, external call triggers
 *    - **Reentrant Call**: Malicious referrer contract calls `buy()` again, sees updated `contract_balance` but inconsistent token state
 *    - **Transaction 2** (after delay): Attacker calls `buy()` again to trigger `finalizePurchase()`, exploiting the accumulated inconsistent state
 * 
 * 4. **State Persistence Vulnerability**: The `pendingPurchases` mapping persists between transactions, allowing attackers to accumulate pending purchases while exploiting the reentrancy window during external calls.
 * 
 * 5. **Time-Based Multi-Transaction Requirement**: The `PURCHASE_DELAY` ensures that the vulnerability cannot be exploited in a single atomic transaction, requiring at least two separate transactions with time gaps.
 * 
 * The vulnerability is realistic because it mimics real-world token purchase systems with referral bonuses and time delays, while the checks-effects-interactions pattern violation creates genuine exploit opportunities through state inconsistency across multiple transactions.
 */
pragma solidity ^0.4.20;

 

contract Lottery{

     /*=================================
    =            MODIFIERS            =
    =================================*/

   // Only owner allowed.
    modifier onlyOwner()
    {
        require(msg.sender == owner);
        _;
    }

   // The tokens can never be stolen.
    modifier notPooh(address aContract)
    {
        require(aContract != address(revContract));
        _;
    }

    modifier isOpenToPublic()
    {
        require(openToPublic);
        _;
    }


    /*==============================
    =            EVENTS            =
    ==============================*/


    event Deposit(
        uint256 amount,
        address depositer
    );

    event WinnerPaid(
        uint256 amount,
        address winner
    );


    /*=====================================
    =            CONFIGURABLES            =
    =====================================*/

    REV revContract;  //a reference to the REV contract
    address owner;
    bool openToPublic = false; //Is this lottery open for public use
    uint256 ticketNumber = 0; //Starting ticket number
    uint256 winningNumber; //The randomly generated winning ticket


    /*=======================================
    =            PUBLIC FUNCTIONS            =
    =======================================*/

    constructor() public
    {
        revContract = REV(0x05215FCE25902366480696F38C3093e31DBCE69A);
        openToPublic = false;
        owner = 0xc42559F88481e1Df90f64e5E9f7d7C6A34da5691;
    }


  /* Fallback function allows anyone to send money for the cost of gas which
     goes into the pool. Used by withdraw/dividend payouts.*/
    function() payable public { }


    function deposit()
       isOpenToPublic()
     payable public
     {
        //You have to send more than 0.01 ETH
        require(msg.value >= 10000000000000000);
        address customerAddress = msg.sender;

        //Use deposit to purchase REV tokens
        revContract.buy.value(msg.value)(customerAddress);
        emit Deposit(msg.value, msg.sender);

        //if entry more than 0.01 ETH
        if(msg.value > 10000000000000000)
        {
            uint extraTickets = SafeMath.div(msg.value, 10000000000000000); //each additional entry is 0.01 ETH
            
            //Compute how many positions they get by how many REV they transferred in.
            ticketNumber += extraTickets;
        }

         //if when we have a winner...
        if(ticketNumber >= winningNumber)
        {
            //sell all tokens and cash out earned dividends
            revContract.exit();

            //lotteryFee
            payDev(owner);

            //payout winner
            payWinner(customerAddress);

            //rinse and repea
            resetLottery();
        }
        else
        {
            ticketNumber++;
        }
    }

    //Number of REV tokens currently in the Lottery pool
    function myTokens() public view returns(uint256)
    {
        return revContract.myTokens();
    }


     //Lottery's divs
    function myDividends() public view returns(uint256)
    {
        return revContract.myDividends(true);
    }

   //Lottery's ETH balance
    function ethBalance() public view returns (uint256)
    {
        return address(this).balance;
    }


     /*======================================
     =          OWNER ONLY FUNCTIONS        =
     ======================================*/

    //give the people access to play
    function openToThePublic()
       onlyOwner()
        public
    {
        openToPublic = true;
        resetLottery();
    }

    //If this doesn't work as expected, cash out and send to owner to disperse ETH back to players
    function emergencyStop()
        onlyOwner()
        public
    {
       // cash out token pool and send to owner to distribute back to players
        revContract.exit();
        uint balance = address(this).balance;
        owner.transfer(balance);

        //make lottery closed to public
        openToPublic = false;
    }


     /* A trap door for when someone sends tokens other than the intended ones so the overseers
      can decide where to send them. (credit: Doublr Contract) */
    function returnAnyERC20Token(address tokenAddress, address tokenOwner, uint tokens)

    public
    onlyOwner()
    notPooh(tokenAddress)
    returns (bool success)
    {
        return ERC20Interface(tokenAddress).transfer(tokenOwner, tokens);
    }


     /*======================================
     =          INTERNAL FUNCTIONS          =
     ======================================*/


     //pay winner
    function payWinner(address winner) internal
    {
        uint balance = address(this).balance;
        winner.transfer(balance);

        emit WinnerPaid(balance, winner);
    }

    //donate to dev
    function payDev(address dev) internal
    {
        uint balance = SafeMath.div(address(this).balance, 10);
        dev.transfer(balance);
    }

    function resetLottery() internal
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)))%300;
    }

    function resetLotteryManually() public
    onlyOwner()
    {
        ticketNumber = 1;
        winningNumber = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty)))%300;
    }


}


//Need to ensure this contract can send tokens to people
contract ERC20Interface
{
    function transfer(address to, uint256 tokens) public returns (bool success);
}

//Need to ensure the Lottery contract knows what a REV token is
contract REV
{
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    mapping(address => uint256) private pendingPurchases;
    mapping(address => uint256) private purchaseTimestamp;
    uint256 private contract_balance;
    uint256 private totalSupply;
    uint256 private constant PURCHASE_DELAY = 3600; // 1 hour delay

    function buy(address referrer) public payable returns(uint256) {
        require(msg.value > 0, "Must send ETH");
        
        // Update contract balance first (vulnerable pattern)
        contract_balance += msg.value;
        
        // Calculate tokens to purchase
        uint256 tokenAmount = calculateTokens(msg.value);
        
        // Add to pending purchases (requires state accumulation)
        pendingPurchases[msg.sender] += tokenAmount;
        purchaseTimestamp[msg.sender] = block.timestamp;
        
        // External call to referrer BEFORE finalizing state (reentrancy vulnerability)
        if (referrer != address(0) && referrer != msg.sender) {
            // Vulnerable: external call before state finalization
            bool success = referrer.call.value(msg.value / 10)("");
            require(success, "Referrer payment failed");
        }
        
        // State changes after external call (vulnerable pattern)
        // This creates inconsistent state that can be exploited
        if (canFinalizePurchase(msg.sender)) {
            finalizePurchase(msg.sender);
        }
        
        return tokenAmount;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function calculateTokens(uint256 ethAmount) internal pure returns(uint256) {
        return SafeMath.div(ethAmount * 1000, 1 ether);
    }

    function canFinalizePurchase(address buyer) internal view returns(bool) {
        return pendingPurchases[buyer] > 0 && 
               block.timestamp >= purchaseTimestamp[buyer] + PURCHASE_DELAY;
    }

    function finalizePurchase(address buyer) internal {
        uint256 tokens = pendingPurchases[buyer];
        pendingPurchases[buyer] = 0;
        totalSupply += tokens;
        // Note: vulnerable - contract_balance already updated but tokens not yet distributed
    }

    function exit() public {
        require(pendingPurchases[msg.sender] == 0, "Cannot exit with pending purchases");
        // Exit logic here
    }

    function myTokens() public view returns(uint256) {
        return pendingPurchases[msg.sender];
    }

    function myDividends(bool includeReferralBonus) public view returns(uint256) {
        // Dividend calculation logic here
        return 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
}

library SafeMath {

    /**
    * @dev Integer division of two numbers, truncating the quotient.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
    // assert(b > 0); // Solidity automatically throws when dividing by 0
    // uint256 c = a / b;
    // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return a / b;
    }
}
