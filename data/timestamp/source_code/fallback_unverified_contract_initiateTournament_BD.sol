/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTournament
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a multi-transaction timestamp dependence issue in tournament functionality. The vulnerability requires: 1) Tournament creation with initiateTournament() 2) Multiple players joining via joinTournament() 3) Tournament finalization via finalizeTournament(). The vulnerability lies in the timestamp-dependent winner selection algorithm where miners can manipulate block.timestamp to influence the winner selection. The tournament state persists across multiple transactions, making this a stateful vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract Esportsblock {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Tournament state variables
    struct Tournament {
        uint256 entryFee;
        uint256 prizePool;
        uint256 endTime;
        address winner;
        bool active;
        bool finalized;
        mapping(address => bool) participants;
        address[] participantList;
    }
    
    mapping(uint256 => Tournament) public tournaments;
    uint256 public tournamentCounter = 0;
    
    event TournamentCreated(uint256 indexed tournamentId, uint256 entryFee, uint256 endTime);
    event TournamentJoined(uint256 indexed tournamentId, address indexed participant);
    event TournamentFinalized(uint256 indexed tournamentId, address indexed winner, uint256 prize);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function Esportsblock() public {
        totalSupply = 86000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = 'Esportsblock';                                   // Set the name for display purposes
        symbol = 'ESB';                               // Set the symbol for display purposes
    }

    /**
     * Initialize a new tournament
     *
     * Creates a new tournament with entry fee and duration
     * Tournament can be finalized after endTime using block.timestamp
     *
     * @param _entryFee Entry fee in tokens
     * @param _duration Duration in seconds
     */
    function initiateTournament(uint256 _entryFee, uint256 _duration) public returns (uint256 tournamentId) {
        require(_entryFee > 0);
        require(_duration > 0);
        
        tournamentCounter++;
        tournamentId = tournamentCounter;
        
        tournaments[tournamentId].entryFee = _entryFee;
        tournaments[tournamentId].prizePool = 0;
        tournaments[tournamentId].endTime = now + _duration;  // VULNERABILITY: Timestamp dependence
        tournaments[tournamentId].active = true;
        tournaments[tournamentId].finalized = false;
        
        TournamentCreated(tournamentId, _entryFee, tournaments[tournamentId].endTime);
        return tournamentId;
    }
    
    /**
     * Join a tournament
     *
     * Allows players to join an active tournament by paying entry fee
     * Must be called before tournament end time
     *
     * @param _tournamentId Tournament ID to join
     */
    function joinTournament(uint256 _tournamentId) public {
        Tournament storage tournament = tournaments[_tournamentId];
        
        require(tournament.active);
        require(!tournament.finalized);
        require(now < tournament.endTime);  // VULNERABILITY: Timestamp dependence
        require(!tournament.participants[msg.sender]);
        require(balanceOf[msg.sender] >= tournament.entryFee);
        
        // Transfer entry fee to contract
        balanceOf[msg.sender] -= tournament.entryFee;
        tournament.prizePool += tournament.entryFee;
        
        // Add participant
        tournament.participants[msg.sender] = true;
        tournament.participantList.push(msg.sender);
        
        TournamentJoined(_tournamentId, msg.sender);
    }
    
    /**
     * Finalize tournament and distribute prize
     *
     * Can only be called after tournament end time
     * Winner is selected based on timestamp manipulation vulnerability
     *
     * @param _tournamentId Tournament ID to finalize
     */
    function finalizeTournament(uint256 _tournamentId) public {
        Tournament storage tournament = tournaments[_tournamentId];
        
        require(tournament.active);
        require(!tournament.finalized);
        require(now >= tournament.endTime);  // VULNERABILITY: Timestamp dependence
        require(tournament.participantList.length > 0);
        
        // VULNERABILITY: Winner selection based on timestamp - miners can manipulate
        uint256 winnerIndex = (now * block.difficulty) % tournament.participantList.length;
        address winner = tournament.participantList[winnerIndex];
        
        // Transfer prize to winner
        balanceOf[winner] += tournament.prizePool;
        
        tournament.winner = winner;
        tournament.finalized = true;
        tournament.active = false;
        
        TournamentFinalized(_tournamentId, winner, tournament.prizePool);
    }
    
    /**
     * Get tournament participants count
     *
     * @param _tournamentId Tournament ID
     */
    function getTournamentParticipants(uint256 _tournamentId) public view returns (uint256) {
        return tournaments[_tournamentId].participantList.length;
    }
    // === END FALLBACK INJECTION ===

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}