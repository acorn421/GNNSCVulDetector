/*
 * ===== SmartInject Injection Details =====
 * Function      : resetLotteryManually
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability where:
 * 
 * 1. **Stateful Timestamp Tracking**: Added `lastResetTimestamp` and `resetCount` state variables to track timing patterns across multiple function calls.
 * 
 * 2. **Cumulative Timing Manipulation**: The vulnerability allows the owner to perform rapid successive resets (within 60-second windows) to accumulate advantages that lower the `winningNumber`, making the lottery end sooner.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Owner calls `resetLotteryManually()` to establish baseline timestamp
 *    - **Transaction 2+**: Owner performs rapid successive resets within 60-second windows
 *    - Each rapid reset accumulates advantages (`resetCount * 10`) and applies time-based multipliers
 *    - The accumulated state changes persist between transactions and compound the advantage
 * 
 * 4. **Time-Based State Accumulation**: The `resetCount` increments with each call and provides cumulative bonuses when combined with timestamp manipulation, requiring multiple transactions to build up significant advantages.
 * 
 * 5. **Realistic Exploitation**: An attacker (owner) could:
 *    - Monitor the mempool for incoming deposits
 *    - Perform multiple rapid resets to manipulate the `winningNumber` to a favorable low value
 *    - Time the final reset to ensure the next deposit(s) will trigger a win
 *    - Use the accumulated `resetCount` bonuses to guarantee wins
 * 
 * The vulnerability is not exploitable in a single transaction because it requires building up state (`resetCount`, timing patterns) over multiple calls to achieve meaningful manipulation of the lottery outcome.
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
    
    // Variables needed for resetLotteryManually
    uint256 public lastResetTimestamp = 0;
    uint256 public resetCount = 0;


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
        winningNumber = uint256(keccak256(block.timestamp, block.difficulty))%300;
    }

    function resetLotteryManually() public
    onlyOwner()
    {
        ticketNumber = 1;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Store block timestamp for accumulated timing manipulation
        if(lastResetTimestamp == 0) {
            lastResetTimestamp = block.timestamp;
        }
        
        // Calculate time-based multiplier that accumulates over multiple resets
        uint256 timeDelta = block.timestamp - lastResetTimestamp;
        uint256 timeMultiplier = (timeDelta / 300) + 1; // Increases every 5 minutes
        
        // Apply accumulated timing advantages to winning number calculation
        uint256 baseWinning = uint256(keccak256(block.timestamp, block.difficulty)) % 300;
        
        // Owner can accumulate timing advantages over multiple resets
        if(resetCount > 0 && timeDelta < 60) {
            // Rapid resets within 1 minute provide cumulative advantage
            winningNumber = (baseWinning / timeMultiplier) + (resetCount * 10);
            if(winningNumber < 50) winningNumber = 50; // Ensure minimum threshold
        } else {
            winningNumber = baseWinning;
            resetCount = 0; // Reset counter for non-rapid resets
        }
        
        resetCount++;
        lastResetTimestamp = block.timestamp;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
    function buy(address) public payable returns(uint256);
    function exit() public;
    function myTokens() public view returns(uint256);
    function myDividends(bool) public view returns(uint256);
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