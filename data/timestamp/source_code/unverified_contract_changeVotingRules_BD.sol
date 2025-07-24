/*
 * ===== SmartInject Injection Details =====
 * Function      : changeVotingRules
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 13 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction Timestamp Dependence vulnerability through two mechanisms:
 * 
 * **Changes Made:**
 * 1. **Governance Window Logic**: Added timestamp-based restrictions that only allow rule changes during the first 7 days of every 30-day cycle, calculated using `block.timestamp`
 * 2. **Cooldown Period**: Introduced a 24-hour cooldown between rule changes using `lastRuleChangeTime` state variable and `block.timestamp` comparisons
 * 3. **State Persistence**: Added `lastRuleChangeTime` storage that persists between transactions
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 - Setup Phase:**
 * - Attacker waits for or manipulates timing to be within a governance window
 * - Calls `changeVotingRules()` to set initial malicious parameters
 * - This establishes `lastRuleChangeTime` in contract state
 * 
 * **Transaction 2+ - Exploitation Phase:**
 * - Attacker (if they have mining power or can influence block timestamps) can manipulate `block.timestamp` in subsequent blocks
 * - By manipulating timestamps, they can bypass the 24-hour cooldown and governance window restrictions
 * - They can rapidly change voting rules multiple times to:
 *   - Reduce `minimumQuorum` to make proposals easier to pass
 *   - Reduce `debatingPeriodInMinutes` to rush through malicious proposals
 *   - Change `minShare` requirements to exclude other voters
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * 1. **State Accumulation**: The `lastRuleChangeTime` must be set in a previous transaction before the cooldown logic can be exploited
 * 2. **Sequential Dependency**: Each rule change affects subsequent governance decisions, requiring multiple transactions to achieve full exploitation
 * 3. **Timing Windows**: The governance window restriction means attackers need multiple opportunities across different blocks to fully exploit the system
 * 4. **Block Timestamp Manipulation**: Miners can only manipulate timestamps across multiple blocks, not within a single transaction
 * 
 * **Real-World Impact:**
 * This vulnerability mirrors real-world DAO governance attacks where timestamp manipulation allows malicious actors to bypass intended governance safeguards across multiple blocks, gradually compromising the entire governance system through accumulated state changes.
 */
pragma solidity ^0.4.16;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  /**
   * @dev The Ownable constructor sets the original `owner` of the contract to the sender
   * account.
   */
  constructor() public {
    owner = msg.sender;
  }

  /**
   * @dev Throws if called by any account other than the owner.
   */
  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  /**
   * @dev Allows the current owner to transfer control of the contract to a newOwner.
   * @param newOwner The address to transfer ownership to.
   */
  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}


contract tokenRecipient {
  event receivedEther(address sender, uint amount);
  event receivedTokens(address _from, uint256 _value, address _token, bytes _extraData);

  function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public {
    Token t = Token(_token);
    require(t.transferFrom(_from, this, _value));
    receivedTokens(_from, _value, _token, _extraData);
  }

  function () payable public {
    receivedEther(msg.sender, msg.value);
  }
}

contract Token {
  mapping (address => uint256) public balanceOf;
  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

/**
 * QWoodDAO contract
 */
contract QWoodDAO is Ownable, tokenRecipient {

  uint public minimumQuorum;
  uint public debatingPeriodInMinutes;
  Proposal[] public proposals;
  uint public numProposals;
  Token public sharesTokenAddress;
  uint256 public minShare;
  uint256 public lastRuleChangeTime; // <-- Added declaration for lastRuleChangeTime

  event ProposalAdded(uint proposalID, address recipient, uint amount, string description);
  event Voted(uint proposalID, bool position, address voter);
  event ProposalTallied(uint proposalID, uint result, uint quorum, bool active);
  event ChangeOfRules(uint newMinimumQuorum, uint newDebatingPeriodInMinutes, address newSharesTokenAddress, uint256 newMinShare);

  struct Proposal {
    address recipient;
    uint amount;
    string description;
    uint minExecutionDate;
    bool executed;
    bool proposalPassed;
    uint numberOfVotes;
    bytes32 proposalHash;
    Vote[] votes;
    mapping (address => bool) voted;
  }

  struct Vote {
    bool inSupport;
    address voter;
  }

  // Modifier that allows only shareholders to vote and create new proposals
  modifier onlyShareholders {
    require(sharesTokenAddress.balanceOf(msg.sender) > minShare);
    _;
  }

  /**
   * Constructor function
   *
   * First time setup
   */
  constructor(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) payable public {
    changeVotingRules(sharesAddress, minimumSharesToPassAVote, minutesForDebate, minimumShare);
  }

  /**
   * Change voting rules
   *
   * Make so that proposals need to be discussed for at least `minutesForDebate/60` hours
   * and all voters combined must own more than `minimumSharesToPassAVote` shares of token `sharesAddress` to be executed
   *
   * @param sharesAddress token address
   * @param minimumSharesToPassAVote proposal can vote only if the sum of shares held by all voters exceed this number
   * @param minutesForDebate the minimum amount of delay between when a proposal is made and when it can be executed
   * @param minimumShare the minimum share of shareholders
   */
  function changeVotingRules(Token sharesAddress, uint minimumSharesToPassAVote, uint minutesForDebate, uint256 minimumShare) onlyOwner public {
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
    // Timestamp-based governance window: rules can only be changed during "governance periods"
    // which are the first 7 days of every 30-day cycle, starting from contract deployment
    uint256 cycleLength = 30 days;
    uint256 governanceWindow = 7 days;
    uint256 currentCycle = (block.timestamp) / cycleLength;
    uint256 cycleStart = currentCycle * cycleLength;
    uint256 timeSinceCycleStart = block.timestamp - cycleStart;
    
    // Check if we're in a governance window
    require(timeSinceCycleStart <= governanceWindow, "Rule changes only allowed during governance window");
    
    // Additional vulnerability: timestamp-based cooldown between rule changes
    // Store the timestamp of last rule change
    if (lastRuleChangeTime == 0) {
        lastRuleChangeTime = block.timestamp;
    } else {
        // Require at least 24 hours between rule changes, but use block.timestamp for comparison
        require(block.timestamp >= lastRuleChangeTime + 1 days, "Must wait 24 hours between rule changes");
        lastRuleChangeTime = block.timestamp;
    }
    
    // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    sharesTokenAddress = Token(sharesAddress);
    if (minimumSharesToPassAVote == 0 ) minimumSharesToPassAVote = 1;
    minimumQuorum = minimumSharesToPassAVote;
    debatingPeriodInMinutes = minutesForDebate;
    minShare = minimumShare;
    ChangeOfRules(minimumQuorum, debatingPeriodInMinutes, sharesTokenAddress, minShare);
  }

  /**
   * Add Proposal
   *
   * Propose to send `weiAmount / 1e18` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   *
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send, in wei
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposal(
    address beneficiary,
    uint weiAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    proposalID = proposals.length++;
    Proposal storage p = proposals[proposalID];
    p.recipient = beneficiary;
    p.amount = weiAmount;
    p.description = jobDescription;
    p.proposalHash = keccak256(beneficiary, weiAmount, transactionBytecode);
    p.minExecutionDate = now + debatingPeriodInMinutes * 1 minutes;
    p.executed = false;
    p.proposalPassed = false;
    p.numberOfVotes = 0;
    ProposalAdded(proposalID, beneficiary, weiAmount, jobDescription);
    numProposals = proposalID+1;

    return proposalID;
  }

  /**
   * Add proposal in Ether
   *
   * Propose to send `etherAmount` ether to `beneficiary` for `jobDescription`. `transactionBytecode ? Contains : Does not contain` code.
   * This is a convenience function to use if the amount to be given is in round number of ether units.
   *
   * @param beneficiary who to send the ether to
   * @param etherAmount amount of ether to send
   * @param jobDescription Description of job
   * @param transactionBytecode bytecode of transaction
   */
  function newProposalInEther(
    address beneficiary,
    uint etherAmount,
    string jobDescription,
    bytes transactionBytecode
  )
  onlyShareholders public
  returns (uint proposalID)
  {
    return newProposal(beneficiary, etherAmount * 1 ether, jobDescription, transactionBytecode);
  }

  /**
   * Check if a proposal code matches
   *
   * @param proposalNumber ID number of the proposal to query
   * @param beneficiary who to send the ether to
   * @param weiAmount amount of ether to send
   * @param transactionBytecode bytecode of transaction
   */
  function checkProposalCode(
    uint proposalNumber,
    address beneficiary,
    uint weiAmount,
    bytes transactionBytecode
  )
  constant public
  returns (bool codeChecksOut)
  {
    Proposal storage p = proposals[proposalNumber];
    return p.proposalHash == keccak256(beneficiary, weiAmount, transactionBytecode);
  }

  /**
   * Log a vote for a proposal
   *
   * Vote `supportsProposal? in support of : against` proposal #`proposalNumber`
   *
   * @param proposalNumber number of proposal
   * @param supportsProposal either in favor or against it
   */
  function vote(
    uint proposalNumber,
    bool supportsProposal
  )
  onlyShareholders public
  returns (uint voteID)
  {
    Proposal storage p = proposals[proposalNumber];
    require(p.voted[msg.sender] != true);

    voteID = p.votes.length++;
    p.votes[voteID] = Vote({inSupport: supportsProposal, voter: msg.sender});
    p.voted[msg.sender] = true;
    p.numberOfVotes = voteID +1;
    Voted(proposalNumber,  supportsProposal, msg.sender);
    return voteID;
  }

  /**
   * Finish vote
   *
   * Count the votes proposal #`proposalNumber` and execute it if approved
   *
   * @param proposalNumber proposal number
   * @param transactionBytecode optional: if the transaction contained a bytecode, you need to send it
   */
  function executeProposal(uint proposalNumber, bytes transactionBytecode) public {
    Proposal storage p = proposals[proposalNumber];

    require(now > p.minExecutionDate                                             // If it is past the voting deadline
    && !p.executed                                                          // and it has not already been executed
    && p.proposalHash == keccak256(p.recipient, p.amount, transactionBytecode)); // and the supplied code matches the proposal...


    // ...then tally the results
    uint quorum = 0;
    uint yea = 0;
    uint nay = 0;

    for (uint i = 0; i <  p.votes.length; ++i) {
      Vote storage v = p.votes[i];
      uint voteWeight = sharesTokenAddress.balanceOf(v.voter);
      quorum += voteWeight;
      if (v.inSupport) {
        yea += voteWeight;
      } else {
        nay += voteWeight;
      }
    }

    require(quorum >= minimumQuorum); // Check if a minimum quorum has been reached

    if (yea > nay ) {
      // Proposal passed; execute the transaction

      p.executed = true;
      require(p.recipient.call.value(p.amount)(transactionBytecode));

      p.proposalPassed = true;
    } else {
      // Proposal failed
      p.proposalPassed = false;
    }

    // Fire Events
    ProposalTallied(proposalNumber, yea - nay, quorum, p.proposalPassed);
  }
}